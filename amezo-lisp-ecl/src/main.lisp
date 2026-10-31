;;;; main.lisp - 起動点: サーバ / --make-hash / --cgi / archive サブコマンド
(in-package :amezo)

(defun normalize-argv (argv)
  "ecl --norc --shell amezo.lisp -- ARGS... の ARGS だけにする。
   最初の -- より前 (ecl 自身、オプション、スクリプト名) は捨てる。-- が無ければ全部を引数とみなさない。"
  (let ((rest (member "--" argv :test #'string=)))
    (copy-list (rest rest))))

(defun print-hash-and-exit (password)
  (format t "~a~%" (make-hash password))
  0)

(defun write-delpass (password)
  (if (zerop (length password))
      (progn (format *error-output* "❌ 合言葉が空です。~%") 1)
      (progn (write-file-string (app-path "delpass.txt") (format nil "~a~%" (make-hash password)))
             (chmod-file (app-path "delpass.txt") #o600)
             (format t "✅ delpass.txt を作りました。管理画面は /admin.cgi です。~%")
             0)))

(defun cgi-env-request (script-base body)
  (let ((headers '()))
    (dolist (pair '(("Referer" . "HTTP_REFERER") ("Origin" . "HTTP_ORIGIN") ("Host" . "HTTP_HOST")
                    ("User-Agent" . "HTTP_USER_AGENT") ("CF-Connecting-IP" . "HTTP_CF_CONNECTING_IP")
                    ("X-Forwarded-For" . "HTTP_X_FORWARDED_FOR") ("Accept-Encoding" . "HTTP_ACCEPT_ENCODING")))
      (let ((v (ext:getenv (cdr pair)))) (when v (push (cons (car pair) v) headers))))
    (make-request :method (getenv* "REQUEST_METHOD" "GET")
                  :query-string (getenv* "QUERY_STRING")
                  :body body :headers headers
                  :remote-addr (getenv* "REMOTE_ADDR")
                  :script-name (format nil "/~a.cgi" script-base))))

(defun run-cgi (script-base)
  "外部の CGI サーバから呼ばれた場合のモード。標準入力から本体を読み、標準出力へ返す。"
  (let ((n (or (safe-integer (getenv* "CONTENT_LENGTH" "0")) 0)))
    (when (< n 0) (setf n 0))
    (let ((body (make-array n :element-type '(unsigned-byte 8))))
      (when (plusp n)
        (let ((in (ext:make-stream-from-fd 0 :input :element-type '(unsigned-byte 8))))
          (read-sequence body in)))
      (let* ((req (cgi-env-request script-base body))
             (*request* req)
             (resp (handler-case
                       (case (intern (string-upcase script-base) :keyword)
                         (:AMEZO (handle-amezo req))
                         (:DAI (handle-dai req))
                         (:ADMIN (handle-admin req))
                         (:JUMP (handle-jump req))
                         (otherwise (make-response :status 404 :body "Not Found")))
                     (error (e) (make-response :status 500 :body (format nil "Error: ~a" e))))))
        (let ((out (ext:make-stream-from-fd 1 :output :element-type '(unsigned-byte 8))))
          ;; Status: ヘッダ (CGI 式) + その他のヘッダ + 空行 + 本体
          (let ((head (with-output-to-string (s)
                        (format s "Status: ~d~a" (response-status resp) (format nil "~a~a" #\Return #\Newline))
                        (dolist (h (response-headers resp)) (format s "~a: ~a~a" (car h) (cdr h) (format nil "~a~a" #\Return #\Newline)))
                        (format s "~a" (format nil "~a~a" #\Return #\Newline)))))
            (write-sequence (utf8 head) out))
          (write-sequence (utf8 (response-body resp)) out)
          (finish-output out))
        0))))

(defun main (argv)
  (let ((args (normalize-argv argv)))
    ;; アプリのルートを設定 (ローダが *root-dir* を入れてある)
    (setf *app-dir* (or *root-dir* (pathname (format nil "~a/" (ext:getcwd)))))
    (load-config)
    (cond
      ;; archive サブコマンド: amezo.lisp archive ...
      ((and args (member (first args) '("archive" "--archive") :test #'string=))
       (os-exit (archive-main (rest args))))
      ;; --make-hash: ハッシュだけ表示 (Python 版 amezo.py --make-hash と同じ)
      ((and args (string= (first args) "--make-hash"))
       (if (second args)
           (os-exit (print-hash-and-exit (second args)))
           (progn (format *error-output* "Usage: amezo.lisp --make-hash PASSWORD~%") (os-exit 1))))
      ;; --make-delpass: delpass.txt を作る (Python 版 setup_expose.py --make-hash と同じ役割)
      ((and args (string= (first args) "--make-delpass"))
       (os-exit (write-delpass (or (second args) ""))))
      ;; --setup-tunnel: cloudflared を用意する (無ければ自動ダウンロード)
      ((and args (string= (first args) "--setup-tunnel"))
       (os-exit (setup-tunnel-command)))
      ;; --cgi amezo|dai|admin|jump
      ((and args (string= (first args) "--cgi"))
       (os-exit (run-cgi (or (second args) ""))))
      ;; サーバ起動
      (t
       (let ((port 8000) (tunnel nil))
         (loop for rest on args
               for a = (first rest)
               do (cond ((string= a "--port") (setf port (or (safe-integer (second rest)) 8000)))
                        ((string= a "--tunnel") (setf tunnel t))
                        ((string= a "--no-tunnel") nil)
                        ((string= a "--verbose") (setf *verbose* t))
                        (t (format *error-output* "不明な引数: ~a~%" a))))
         (os-exit (serve port :tunnel tunnel)))))))
