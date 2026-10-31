;;;; crypto.lisp - SHA-256 / HMAC / PBKDF2 / base64 / base32 (自前実装、外部依存なし)
;;;; Python 版 (hashlib / hmac / base64) と結果が一致するように作ってある。
(in-package :amezo)

;;; ---------- 汎用 ----------
(defun u32 (x) (ldb (byte 32 0) x))
(defun rotr32 (x n) (u32 (logior (ash x (- n)) (ash x (- 32 n)))))

(defun octets (&rest bytes) (make-array (length bytes) :element-type '(unsigned-byte 8) :initial-contents bytes))


(defun hex-encode (octs)
  (let ((digits "0123456789abcdef"))
    (with-output-to-string (out)
      (loop for b across octs
            do (write-char (char digits (ash b -4)) out)
               (write-char (char digits (logand b 15)) out)))))

(defun hex-decode (s)
  "16進文字列 -> octet vector。壊れていれば NIL。"
  (when (and (evenp (length s))
             (every (lambda (c) (digit-char-p c 16)) s))
    (let ((v (make-array (/ (length s) 2) :element-type '(unsigned-byte 8))))
      (loop for i from 0 below (length s) by 2
            for j from 0
            do (setf (aref v j) (parse-integer s :start i :end (+ i 2) :radix 16)))
      v)))

(defun random-octets (n)
  (let ((v (make-array n :element-type '(unsigned-byte 8))))
    (with-open-file (in "/dev/urandom" :element-type '(unsigned-byte 8))
      (read-sequence v in))
    v))

(defun constant-time-equal (a b)
  (if (/= (length a) (length b))
      nil
      (let ((d 0))
        (loop for x across a for y across b do (setf d (logior d (logxor x y))))
        (zerop d))))

(defun constant-time-string-equal (a b)
  (constant-time-equal (utf8 (or a "")) (utf8 (or b ""))))

;;; ---------- SHA-256 ----------
(defvar *sha256-k*
  #(#x428a2f98 #x71374491 #xb5c0fbcf #xe9b5dba5 #x3956c25b #x59f111f1 #x923f82a4 #xab1c5ed5
    #xd807aa98 #x12835b01 #x243185be #x550c7dc3 #x72be5d74 #x80deb1fe #x9bdc06a7 #xc19bf174
    #xe49b69c1 #xefbe4786 #x0fc19dc6 #x240ca1cc #x2de92c6f #x4a7484aa #x5cb0a9dc #x76f988da
    #x983e5152 #xa831c66d #xb00327c8 #xbf597fc7 #xc6e00bf3 #xd5a79147 #x06ca6351 #x14292967
    #x27b70a85 #x2e1b2138 #x4d2c6dfc #x53380d13 #x650a7354 #x766a0abb #x81c2c92e #x92722c85
    #xa2bfe8a1 #xa81a664b #xc24b8b70 #xc76c51a3 #xd192e819 #xd6990624 #xf40e3585 #x106aa070
    #x19a4c116 #x1e376c08 #x2748774c #x34b0bcb5 #x391c0cb3 #x4ed8aa4a #x5b9cca4f #x682e6ff3
    #x748f82ee #x78a5636f #x84c87814 #x8cc70208 #x90befffa #xa4506ceb #xbef9a3f7 #xc67178f2))

(defstruct (sha256 (:constructor %make-sha256))
  (h (make-array 8 :element-type '(unsigned-byte 32)
                   :initial-contents '(#x6a09e667 #xbb67ae85 #x3c6ef372 #xa54ff53a
                                       #x510e527f #x9b05688c #x1f83d9ab #x5be0cd19)))
  (buf (make-array 64 :element-type '(unsigned-byte 8) :initial-element 0))
  (buf-len 0 :type fixnum)
  (total 0 :type fixnum))

(ffi:clines "
static const unsigned int amezo_k256[64] = {
  0x428a2f98,0x71374491,0xb5c0fbcf,0xe9b5dba5,0x3956c25b,0x59f111f1,0x923f82a4,0xab1c5ed5,
  0xd807aa98,0x12835b01,0x243185be,0x550c7dc3,0x72be5d74,0x80deb1fe,0x9bdc06a7,0xc19bf174,
  0xe49b69c1,0xefbe4786,0x0fc19dc6,0x240ca1cc,0x2de92c6f,0x4a7484aa,0x5cb0a9dc,0x76f988da,
  0x983e5152,0xa831c66d,0xb00327c8,0xbf597fc7,0xc6e00bf3,0xd5a79147,0x06ca6351,0x14292967,
  0x27b70a85,0x2e1b2138,0x4d2c6dfc,0x53380d13,0x650a7354,0x766a0abb,0x81c2c92e,0x92722c85,
  0xa2bfe8a1,0xa81a664b,0xc24b8b70,0xc76c51a3,0xd192e819,0xd6990624,0xf40e3585,0x106aa070,
  0x19a4c116,0x1e376c08,0x2748774c,0x34b0bcb5,0x391c0cb3,0x4ed8aa4a,0x5b9cca4f,0x682e6ff3,
  0x748f82ee,0x78a5636f,0x84c87814,0x8cc70208,0x90befffa,0xa4506ceb,0xbef9a3f7,0xc67178f2 };
#define AM_ROTR(x,n) (((x) >> (n)) | ((x) << (32 - (n))))
static void amezo_sha256_compress(unsigned int *st, const unsigned char *p) {
  unsigned int w[64], a, b, c, d, e, f, g, h, t1, t2; int i;
  for (i = 0; i < 16; i++)
    w[i] = ((unsigned int)p[4*i] << 24) | ((unsigned int)p[4*i+1] << 16) | ((unsigned int)p[4*i+2] << 8) | (unsigned int)p[4*i+3];
  for (i = 16; i < 64; i++) {
    unsigned int s0 = AM_ROTR(w[i-15],7) ^ AM_ROTR(w[i-15],18) ^ (w[i-15] >> 3);
    unsigned int s1 = AM_ROTR(w[i-2],17) ^ AM_ROTR(w[i-2],19) ^ (w[i-2] >> 10);
    w[i] = w[i-16] + s0 + w[i-7] + s1;
  }
  a = st[0]; b = st[1]; c = st[2]; d = st[3]; e = st[4]; f = st[5]; g = st[6]; h = st[7];
  for (i = 0; i < 64; i++) {
    t1 = h + (AM_ROTR(e,6) ^ AM_ROTR(e,11) ^ AM_ROTR(e,25)) + ((e & f) ^ (~e & g)) + amezo_k256[i] + w[i];
    t2 = (AM_ROTR(a,2) ^ AM_ROTR(a,13) ^ AM_ROTR(a,22)) + ((a & b) ^ (a & c) ^ (b & c));
    h = g; g = f; f = e; e = d + t1; d = c; c = b; b = a; a = t1 + t2;
  }
  st[0] += a; st[1] += b; st[2] += c; st[3] += d; st[4] += e; st[5] += f; st[6] += g; st[7] += h;
}
static void amezo_put_digest(const unsigned int *st, unsigned char *out) {
  int i; for (i = 0; i < 8; i++) { out[4*i] = st[i] >> 24; out[4*i+1] = st[i] >> 16; out[4*i+2] = st[i] >> 8; out[4*i+3] = st[i]; }
}
/* PBKDF2-HMAC-SHA256 の 2 回目以降の繰り返し。key64: 64 バイトに揃えた鍵。u: U1 (32B)。acc: U1 で始め、最後に T になる。 */
static void amezo_pbkdf2_iter(const unsigned char *key64, unsigned char *u, unsigned char *acc, long n) {
  static const unsigned int H0[8] = {0x6a09e667,0xbb67ae85,0x3c6ef372,0xa54ff53a,0x510e527f,0x9b05688c,0x1f83d9ab,0x5be0cd19};
  unsigned char blk[64]; unsigned int is[8], os[8], st[8]; int i; long k;
  for (i = 0; i < 64; i++) blk[i] = key64[i] ^ 0x36;
  memcpy(is, H0, 32); amezo_sha256_compress(is, blk);
  for (i = 0; i < 64; i++) blk[i] = key64[i] ^ 0x5c;
  memcpy(os, H0, 32); amezo_sha256_compress(os, blk);
  for (k = 0; k < n; k++) {
    memcpy(blk, u, 32); blk[32] = 0x80; memset(blk + 33, 0, 29); blk[62] = 0x03; blk[63] = 0x00;
    memcpy(st, is, 32); amezo_sha256_compress(st, blk); amezo_put_digest(st, blk);
    blk[32] = 0x80; memset(blk + 33, 0, 29); blk[62] = 0x03; blk[63] = 0x00;
    memcpy(st, os, 32); amezo_sha256_compress(st, blk); amezo_put_digest(st, u);
    for (i = 0; i < 32; i++) acc[i] ^= u[i];
  }
}
")

(defun sha256-compress (state block offset)
  "STATE (8 x u32) に BLOCK の OFFSET から 64 バイトを圧縮する。重い部分は C (ECL の ffi:c-inline)。
   純 Lisp 版は ECL では 1 ブロック約 30µs かかり PBKDF2 (10万回) が 16 秒以上になるため。"
  (declare (type (simple-array (unsigned-byte 32) (8)) state)
           (type (simple-array (unsigned-byte 8) (*)) block)
           (type fixnum offset))
  (when (> (+ offset 64) (length block)) (error "sha256-compress: ブロックが足りません"))
  (ffi:c-inline (state block offset) (:object :object :fixnum) :void
                "amezo_sha256_compress((unsigned int*)(#0)->vector.self.b32, (#1)->vector.self.b8 + #2)"
                :one-liner t :side-effects t)
  state)

(defun sha256-update (ctx octs &optional (start 0) (end (length octs)))
  (let* ((len (- end start))
         (buf (sha256-buf ctx))
         (bl (sha256-buf-len ctx)))
    (incf (sha256-total ctx) len)
    (let ((i start))
      ;; 既存の端数と合わせて 64 バイトになれば圧縮
      (when (and (plusp bl) (< bl 64))
        (let ((take (min (- 64 bl) len)))
          (replace buf octs :start1 bl :start2 i :end2 (+ i take))
          (incf i take) (incf bl take)
          (when (= bl 64)
            (sha256-compress (sha256-h ctx) buf 0)
            (setf bl 0))))
      ;; 本体を直接圧縮
      (loop while (<= (+ i 64) end)
            do (sha256-compress (sha256-h ctx) octs i)
               (incf i 64))
      ;; 端数
      (let ((rem (- end i)))
        (when (plusp rem)
          (replace buf octs :start1 0 :start2 i :end2 end)
          (setf bl rem)))
      (setf (sha256-buf-len ctx) bl)))
  ctx)

(defun sha256-final (ctx)
  (let ((bitlen (* (sha256-total ctx) 8))
        (buf (sha256-buf ctx))
        (bl (sha256-buf-len ctx)))
    ;; パディング: 0x80, 0..., 長さ(64bit BE)。total は変わってしまうので先に取ってある
    (let ((pad (make-array 72 :element-type '(unsigned-byte 8) :initial-element 0)))
      (setf (aref pad 0) #x80)
      (let ((padlen (if (< bl 56) (- 56 bl) (- 120 bl))))
        ;; padlen バイト (0x80 を含む) + 8 バイト長
        (loop for i from (- 8 1) downto 0
              for j from 0
              do (setf (aref pad (+ padlen j)) (ldb (byte 8 (* i 8)) bitlen)))
        ;; sha256-update は total を増やすが、ここではもう使わない
        (sha256-update ctx pad 0 (+ padlen 8))))
    (let ((out (make-array 32 :element-type '(unsigned-byte 8))))
      (loop for i from 0 below 8
            for v = (aref (sha256-h ctx) i)
            do (loop for j from 0 below 4
                     do (setf (aref out (+ (* i 4) j)) (ldb (byte 8 (* (- 3 j) 8)) v))))
      out)))

(defun sha256-octets (octs)
  (let ((ctx (%make-sha256)))
    (sha256-update ctx octs)
    (sha256-final ctx)))

(defun sha256-hex (octs) (hex-encode (sha256-octets octs)))

(defun sha256-file (path)
  "ファイルの SHA-256 を [hex 長さ] で返す。読めなければ NIL (archive 用)。"
  (handler-case
      (let ((ctx (%make-sha256)) (n 0)
            (buf (make-array 65536 :element-type '(unsigned-byte 8))))
        (with-open-file (in path :element-type '(unsigned-byte 8))
          (loop for c = (read-sequence buf in)
                while (plusp c)
                do (sha256-update ctx buf 0 c) (incf n c)))
        (values (hex-encode (sha256-final ctx)) n))
    (error () (values nil nil))))

;;; ---------- HMAC-SHA256 ----------
(defun hmac-sha256 (key msg)
  (let ((k (if (> (length key) 64) (sha256-octets key) key)))
    (let ((kp (make-array 64 :element-type '(unsigned-byte 8) :initial-element 0)))
      (replace kp k)
      (let ((inner (make-array (+ 64 (length msg)) :element-type '(unsigned-byte 8)))
            (outer (make-array (+ 64 32) :element-type '(unsigned-byte 8))))
        (loop for i from 0 below 64 do (setf (aref inner i) (logxor (aref kp i) #x36)))
        (replace inner msg :start1 64)
        (let ((ih (sha256-octets inner)))
          (loop for i from 0 below 64 do (setf (aref outer i) (logxor (aref kp i) #x5c)))
          (replace outer ih :start1 64)
          (sha256-octets outer))))))

(defun hmac-sha256-hex (key msg) (hex-encode (hmac-sha256 key msg)))

;;; ---------- PBKDF2-HMAC-SHA256 (Python の hashlib.pbkdf2_hmac と同じ) ----------
;; 1回目の U1 = HMAC(password, salt || INT(i)) は任意長なので hmac-sha256 で求め、
;; 2回目以降 (32 バイト入力に固定) の繰り返しは C のループに任せる。
(defun pbkdf2-sha256 (password salt iterations dklen)
  (let* ((out (make-array dklen :element-type '(unsigned-byte 8)))
         (key (if (> (length password) 64) (sha256-octets password) password))
         (key64 (make-array 64 :element-type '(unsigned-byte 8) :initial-element 0))
         (pos 0)
         (block-index 1))
    (replace key64 key)
    (loop while (< pos dklen)
          do (let ((msg (make-array (+ (length salt) 4) :element-type '(unsigned-byte 8))))
               (replace msg salt)
               (loop for j from 0 below 4
                     do (setf (aref msg (+ (length salt) j))
                              (ldb (byte 8 (* (- 3 j) 8)) block-index)))
               (let* ((u (coerce (hmac-sha256 password msg) '(simple-array (unsigned-byte 8) (*))))
                      (acc (copy-seq u))
                      (n (max 0 (1- iterations))))
                 (when (plusp n)
                   (ffi:c-inline (key64 u acc n) (:object :object :object :long) :void
                                 "amezo_pbkdf2_iter((unsigned char*)(#0)->vector.self.b8, (unsigned char*)(#1)->vector.self.b8, (unsigned char*)(#2)->vector.self.b8, #3)"
                                 :one-liner t :side-effects t))
                 (let ((take (min 32 (- dklen pos))))
                   (replace out acc :start1 pos :end2 take)
                   (incf pos take)
                   (incf block-index)))))
    out))

;;; ---------- パスワードハッシュ (pbkdf2_sha256$回数$salt.hex$hash.hex) ----------
(defparameter *hash-scheme* "pbkdf2_sha256")

(defun make-hash (password &key (iterations *hash-iterations*) salt)
  (let* ((salt (or salt (random-octets 16)))
         (dk (pbkdf2-sha256 (utf8 password) salt iterations 32)))
    (format nil "~a$~d$~a$~a" *hash-scheme* iterations (hex-encode salt) (hex-encode dk))))

(defun verify-hash (password stored)
  (handler-case
      (let* ((parts (split-string (string-trim '(#\Space #\Tab #\Newline #\Return) (or stored "")) #\$))
             )
        (when (and (= (length parts) 4) (string= (first parts) *hash-scheme*))
          (let ((iters (parse-integer (second parts) :junk-allowed t))
                (salt (hex-decode (third parts)))
                (expected (hex-decode (fourth parts))))
            (when (and iters (<= 1 iters 5000000) salt expected)
              (constant-time-equal (pbkdf2-sha256 (utf8 password) salt iters 32) expected)))))
    (error () nil)))

;;; ---------- base64 / base64url / base32 ----------
(defparameter *b64-alphabet* "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/")
(defparameter *b64url-alphabet* "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_")
(defparameter *b32-alphabet* "ABCDEFGHIJKLMNOPQRSTUVWXYZ234567")

(defun base64-encode (octs &key (alphabet *b64-alphabet*) (padding t))
  (with-output-to-string (out)
    (let ((n (length octs)) (i 0))
      (loop while (< i n)
            for b0 = (aref octs i)
            for b1 = (if (< (+ i 1) n) (aref octs (+ i 1)) 0)
            for b2 = (if (< (+ i 2) n) (aref octs (+ i 2)) 0)
            for v = (logior (ash b0 16) (ash b1 8) b2)
            do (write-char (char alphabet (ldb (byte 6 18) v)) out)
               (write-char (char alphabet (ldb (byte 6 12) v)) out)
               (if (< (+ i 1) n)
                   (write-char (char alphabet (ldb (byte 6 6) v)) out)
                   (when padding (write-char #\= out)))
               (if (< (+ i 2) n)
                   (write-char (char alphabet (ldb (byte 6 0) v)) out)
                   (when padding (write-char #\= out)))
               (incf i 3)))))

(defun b64url-encode (octs) (base64-encode octs :alphabet *b64url-alphabet* :padding nil))

(defun b64url-decode (s)
  "base64url 文字列 -> octet vector。文字種が違う・形が壊れていれば NIL (Python 版と同じ)。"
  (when (and s (plusp (length s))
             (every (lambda (c) (or (alphanumericp c) (char= c #\-) (char= c #\_))) s))
    (handler-case
        (let* ((pad (mod (- (length s)) 4))
               (full (concatenate 'string s (make-string pad :initial-element #\=)))
               (out (make-array (* 3 (/ (length full) 4)) :element-type '(unsigned-byte 8)))
               (pos 0))
          (loop for i from 0 below (length full) by 4
                for vals = (loop for j from 0 below 4
                                 for c = (char full (+ i j))
                                 collect (if (char= c #\=) 0
                                             (position c *b64url-alphabet*)))
                for v = (reduce (lambda (a b) (+ (* a 64) b)) vals)
                do (setf (aref out pos) (ldb (byte 8 16) v)) (incf pos)
                   (unless (char= (char full (+ i 2)) #\=)
                     (setf (aref out pos) (ldb (byte 8 8) v)) (incf pos))
                   (unless (char= (char full (+ i 3)) #\=)
                     (setf (aref out pos) (ldb (byte 8 0) v)) (incf pos)))
          (subseq out 0 pos))
      (error () nil))))

(defun base32-encode (octs)
  "パディングなしの base32 (Python の base64.b32encode から '=' を除いたもの)。"
  (with-output-to-string (out)
    (let ((n (length octs)) (i 0))
      (loop while (< i n)
            for take = (min 5 (- n i))
            for v = (let ((x 0))
                      (loop for j from 0 below 5
                            do (setf x (+ (* x 256)
                                          (if (< j take) (aref octs (+ i j)) 0))))
                      x)
            for chars = (ceiling (* take 8) 5)
            do (loop for j from 0 below chars
                     for shift = (* (- 7 j) 5)
                     do (write-char (char *b32-alphabet* (ldb (byte 5 shift) v)) out))
               (incf i 5)))))
