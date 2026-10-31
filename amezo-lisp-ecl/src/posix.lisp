;;;; posix.lisp - OS 呼び出しの薄い層 (ECL 版)。ffi:clines / ffi:c-inline で libc を直接呼ぶ。
;;;; ※ ffi:c-inline はインタプリタでは使えない。load.lisp が compile-file してから読み込む。
(in-package :amezo)

(ffi:clines "
#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include <signal.h>
#include <fcntl.h>
#include <unistd.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <sys/file.h>
#include <sys/time.h>
#include <dirent.h>
static int amezo_fill(int r, struct stat *st, long *out) {
  if (r != 0) return -1;
  out[0] = (long)st->st_mode;  out[1] = (long)st->st_size;
  out[2] = (long)st->st_mtime; out[3] = (long)st->st_ctime;
  out[4] = (long)st->st_nlink;
  return 0;
}
static int amezo_stat(const char *p, long *out)  { struct stat st; return amezo_fill(stat(p, &st), &st, out); }
static int amezo_fstat(int fd, long *out)        { struct stat st; return amezo_fill(fstat(fd, &st), &st, out); }
static int amezo_utimes(const char *p, long t)   { struct timeval tv[2]; tv[0].tv_sec = t; tv[0].tv_usec = 0; tv[1] = tv[0]; return utimes(p, tv); }
static volatile int amezo_stop = 0;
static void amezo_on_signal(int sig) { amezo_stop = 1; }
static void amezo_install_signals(void) {
  struct sigaction sa; memset(&sa, 0, sizeof sa);
  sa.sa_handler = amezo_on_signal; sigemptyset(&sa.sa_mask);
  sigaction(SIGINT, &sa, NULL); sigaction(SIGTERM, &sa, NULL);
}
static long amezo_listdir(const char *path, unsigned char *buf, long cap) {
  DIR *d = opendir(path); long pos = 0; struct dirent *e;
  if (!d) return -1;
  while ((e = readdir(d)) != NULL) {
    long l = (long)strlen(e->d_name);
    if ((l == 1 && e->d_name[0] == '.') || (l == 2 && e->d_name[0] == '.' && e->d_name[1] == '.')) continue;
    if (pos + l + 1 > cap) break;
    memcpy(buf + pos, e->d_name, l); pos += l; buf[pos++] = 0;
  }
  closedir(d);
  return pos;
}
")

;;; ---------- UTF-8 (文字列 <-> octet vector) ----------
(deftype octets () '(simple-array (unsigned-byte 8) (*)))

(defun utf8 (s)
  "文字列 -> UTF-8 の octet vector"
  (let ((out (make-array (max 16 (* 4 (length s))) :element-type '(unsigned-byte 8) :fill-pointer 0)))
    (loop for ch across s
          for c = (char-code ch)
          do (cond ((< c #x80) (vector-push c out))
                   ((< c #x800)
                    (vector-push (logior #xC0 (ash c -6)) out)
                    (vector-push (logior #x80 (logand c #x3F)) out))
                   ((< c #x10000)
                    (vector-push (logior #xE0 (ash c -12)) out)
                    (vector-push (logior #x80 (logand (ash c -6) #x3F)) out)
                    (vector-push (logior #x80 (logand c #x3F)) out))
                   (t
                    (vector-push (logior #xF0 (ash c -18)) out)
                    (vector-push (logior #x80 (logand (ash c -12) #x3F)) out)
                    (vector-push (logior #x80 (logand (ash c -6) #x3F)) out)
                    (vector-push (logior #x80 (logand c #x3F)) out))))
    (coerce out 'octets)))

(defun latin1-octets (s)
  "文字列 (各文字が 0〜255) -> octet vector。範囲外の文字は ? にする。"
  (let ((v (make-array (length s) :element-type '(unsigned-byte 8))))
    (dotimes (i (length s) v)
      (let ((c (char-code (char s i)))) (setf (aref v i) (if (< c 256) c 63))))))

(defun cstring (x)
  "パス (文字列/pathname) -> NUL 終端の UTF-8 octet vector (C に渡す用)"
  (let* ((o (utf8 (if (pathnamep x) (namestring x) x)))
         (v (make-array (1+ (length o)) :element-type '(unsigned-byte 8) :initial-element 0)))
    (replace v o)
    v))

;;; ---------- 定数 (C の値をそのまま使う) ----------
(defvar +o-rdonly+ (ffi:c-inline () () :int "O_RDONLY" :one-liner t))
(defvar +o-wronly+ (ffi:c-inline () () :int "O_WRONLY" :one-liner t))
(defvar +o-rdwr+   (ffi:c-inline () () :int "O_RDWR" :one-liner t))
(defvar +o-creat+  (ffi:c-inline () () :int "O_CREAT" :one-liner t))
(defvar +o-excl+   (ffi:c-inline () () :int "O_EXCL" :one-liner t))
(defvar +o-trunc+  (ffi:c-inline () () :int "O_TRUNC" :one-liner t))
(defvar +o-append+ (ffi:c-inline () () :int "O_APPEND" :one-liner t))

;;; ---------- stat ----------
(defstruct (st (:constructor make-st (mode size mtime ctime nlink)))
  mode size mtime ctime nlink)

(defun %stat-result (out)
  (make-st (aref out 0) (aref out 1) (aref out 2) (aref out 3) (aref out 4)))

(defun os-stat (path)
  "stat(2)。失敗したらエラー (失敗は呼び出し側の handler-case で拾う)"
  (let ((out (make-array 5 :element-type '(signed-byte 64) :initial-element 0))
        (p (cstring path)))
    (if (zerop (ffi:c-inline (p out) (:object :object) :int
                             "amezo_stat((char*)(#0)->vector.self.b8, (long*)(#1)->vector.self.i64)"
                             :one-liner t))
        (%stat-result out)
        (error "stat 失敗: ~a" path))))

(defun os-fstat (fd)
  (let ((out (make-array 5 :element-type '(signed-byte 64) :initial-element 0)))
    (if (zerop (ffi:c-inline (fd out) (:int :object) :int
                             "amezo_fstat(#0, (long*)(#1)->vector.self.i64)" :one-liner t))
        (%stat-result out)
        (error "fstat 失敗: ~a" fd))))

(defun s-isdir (mode) (= (logand mode #o170000) #o040000))

;;; ---------- ファイル操作 ----------
(defun os-getpid () (ext:getpid))

(defun os-open (path flags mode)
  (let* ((p (cstring path))
         (fd (ffi:c-inline (p flags mode) (:object :int :int) :int
                           "open((char*)(#0)->vector.self.b8, #1, (mode_t)#2)" :one-liner t)))
    (if (< fd 0) (error "open 失敗: ~a" path) fd)))

(defun os-close (fd)
  (ffi:c-inline (fd) (:int) :int "close(#0)" :one-liner t))

(defun os-write (fd octs &optional (n (length octs)))
  "octs の先頭 n バイトを全部書く (部分書き込みは繰り返す)。"
  (let ((done 0))
    (loop while (< done n)
          do (let ((w (ffi:c-inline (fd octs done n) (:int :object :fixnum :fixnum) :fixnum
                                    "write(#0, (#1)->vector.self.b8 + #2, #3 - #2)" :one-liner t)))
               (when (< w 0) (error "write 失敗"))
               (incf done w)))
    done))

(defun os-rename (from to)
  (let ((a (cstring from)) (b (cstring to)))
    (when (/= 0 (ffi:c-inline (a b) (:object :object) :int
                              "rename((char*)(#0)->vector.self.b8, (char*)(#1)->vector.self.b8)" :one-liner t))
      (error "rename 失敗: ~a -> ~a" from to))
    t))

(defun os-link (from to)
  (let ((a (cstring from)) (b (cstring to)))
    (when (/= 0 (ffi:c-inline (a b) (:object :object) :int
                              "link((char*)(#0)->vector.self.b8, (char*)(#1)->vector.self.b8)" :one-liner t))
      (error "link 失敗: ~a -> ~a" from to))
    t))

(defun os-chmod (path mode)
  (let ((p (cstring path)))
    (when (/= 0 (ffi:c-inline (p mode) (:object :int) :int
                              "chmod((char*)(#0)->vector.self.b8, (mode_t)#1)" :one-liner t))
      (error "chmod 失敗: ~a" path))
    t))

(defun os-mkdir (path mode)
  (let ((p (cstring path)))
    (when (/= 0 (ffi:c-inline (p mode) (:object :int) :int
                              "mkdir((char*)(#0)->vector.self.b8, (mode_t)#1)" :one-liner t))
      (error "mkdir 失敗: ~a" path))
    t))

(defun os-utimes (path epoch)
  "更新日時 (とアクセス日時) をエポック秒に設定する。成功で T。"
  (let ((p (cstring path)))
    (zerop (ffi:c-inline (p epoch) (:object :long) :int
                         "amezo_utimes((char*)(#0)->vector.self.b8, #1)" :one-liner t))))

(defun os-kill (pid sig)
  (ffi:c-inline (pid sig) (:int :int) :int "kill(#0, #1)" :one-liner t))

(defun c-flock (fd op)
  (ffi:c-inline (fd op) (:int :int) :int "flock(#0, #1)" :one-liner t))

(defun os-listdir (path)
  "ディレクトリ内の名前 (. と .. を除く) の文字列リスト。開けなければ NIL。"
  (let* ((p (cstring path))
         (buf (make-array 1048576 :element-type '(unsigned-byte 8) :initial-element 0))
         (n (ffi:c-inline (p buf) (:object :object) :fixnum
                          "amezo_listdir((char*)(#0)->vector.self.b8, (#1)->vector.self.b8, (long)(#1)->vector.dim)"
                          :one-liner t)))
    (when (>= n 0)
      (let ((names '()) (start 0))
        (dotimes (i n)
          (when (zerop (aref buf i))
            (push (utf8-decode-simple (subseq buf start i)) names)
            (setf start (1+ i))))
        (nreverse names)))))

(defun utf8-decode-simple (octs)
  "壊れた並びは ? にする簡易版 (ファイル名用)。util.lisp の utf8-decode より先に必要なため。"
  (let ((out (make-string-output-stream)) (n (length octs)) (i 0))
    (loop while (< i n)
          do (let ((b (aref octs i)))
               (flet ((cont (k) (and (< (+ i k) n) (= (logand (aref octs (+ i k)) #xC0) #x80)
                                     (logand (aref octs (+ i k)) #x3F))))
                 (cond ((< b #x80) (write-char (code-char b) out) (incf i))
                       ((and (<= #xC2 b #xDF) (cont 1))
                        (write-char (code-char (logior (ash (logand b #x1F) 6) (cont 1))) out) (incf i 2))
                       ((and (<= #xE0 b #xEF) (cont 1) (cont 2))
                        (write-char (code-char (logior (ash (logand b #x0F) 12) (ash (cont 1) 6) (cont 2))) out) (incf i 3))
                       ((and (<= #xF0 b #xF4) (cont 1) (cont 2) (cont 3))
                        (write-char (code-char (logior (ash (logand b #x07) 18) (ash (cont 1) 12) (ash (cont 2) 6) (cont 3))) out) (incf i 4))
                       (t (write-char #\? out) (incf i))))))
    (get-output-stream-string out)))

;;; ---------- Ctrl+C / SIGTERM ----------
;;; ECL は SIGINT を別スレッドで処理してデバッガに入ってしまうので、フラグを立てるだけの C ハンドラに差し替える。
(defun os-install-stop-signals ()
  (ffi:c-inline () () :void "amezo_install_signals()" :one-liner t :side-effects t))

(defun os-stop-requested-p ()
  (/= 0 (ffi:c-inline () () :int "amezo_stop" :one-liner t :side-effects t)))

;;; ---------- 時刻 / 環境 / 終了 ----------
(defun os-epoch-now ()
  (- (get-universal-time) 2208988800))

(defun os-exit (code)
  "標準出力を流してから終了する。"
  (ignore-errors (finish-output *standard-output*))
  (ignore-errors (finish-output *error-output*))
  (ext:quit code))

;;; ---------- 外部プロセス ----------
(defstruct (proc (:constructor %make-proc)) ext stream)

(defun proc-start (program args &key output-file capture binary merge-error)
  "外部コマンドを起動して待たずに返す (PATH を探す)。
   OUTPUT-FILE: 標準出力をそのファイルへ (上書き) / CAPTURE: 標準出力を stream で受け取る (BINARY なら 1 文字 = 1 バイト)。
   どちらも無ければ標準出力は捨てる。標準エラーは捨てる (MERGE-ERROR なら標準出力へまとめる)。"
  (multiple-value-bind (stream unused ext)
      (apply #'ext:run-program program args
             :wait nil
             :input nil
             :output (cond (capture :stream) (output-file output-file) (t nil))
             :error (if merge-error :output nil)
             (append (when output-file (list :if-output-exists :supersede))
                     (when capture (list :external-format (if binary :latin-1 :utf-8)))))
    (declare (ignore unused))
    (%make-proc :ext ext :stream (and capture stream))))

(defun proc-wait (p)
  "終了を待って終了コードを返す (シグナルで死んだら -1)。"
  (multiple-value-bind (status code) (ext:external-process-wait (proc-ext p) t)
    (if (eq status :exited) code -1)))

(defun proc-kill (p sig)
  (let ((pid (ext:external-process-pid (proc-ext p))))
    (when pid (os-kill pid sig))))

(defun proc-read-octets (p buf)
  "BINARY で起動した p の出力を BUF に読む。読んだバイト数 (0 なら終わり)。"
  (let* ((s (proc-stream p))
         (tmp (make-string (length buf)))
         (n (read-sequence tmp s)))
    (dotimes (i n n) (setf (aref buf i) (logand (char-code (char tmp i)) #xFF)))))

(defun run-status (program args &key output-file)
  "待って終了コードを返す。起動できなければ NIL。"
  (handler-case (proc-wait (proc-start program args :output-file output-file))
    (error () nil)))

(defun run-first-line (program args)
  "標準出力の1行目を返す (成功時のみ)。無ければ NIL。"
  (handler-case
      (let* ((p (proc-start program args :capture t))
             (line (read-line (proc-stream p) nil nil)))
        (and (eql 0 (proc-wait p)) line))
    (error () nil)))
