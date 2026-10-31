;;;; amezo.lisp - 起動スクリプト (ecl --norc --shell amezo.lisp -- ...)
;; ECL は require / コンパイラ読み込み時に ";;; Loading ..." を標準出力へ出す。--make-hash の出力を汚すので止める。
(setf *load-verbose* nil *compile-verbose* nil *compile-print* nil)

(load (merge-pathnames "load.lisp" (make-pathname :name nil :type nil :defaults (or *load-truename* *default-pathname-defaults*)))
      :verbose nil)

(handler-case
    (amezo:main (ext:command-args))
  (error (e)
    (format *error-output* "amezo: ~a~%" e)
    (finish-output *error-output*)
    (ext:quit 1)))
