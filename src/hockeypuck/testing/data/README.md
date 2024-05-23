How to create test vectors
==========================

To create a new test key:

```
gpg --no-default-keyring --keyring ./admin.gpg --quick-generate-key admin@example.com
```

To export a key:

```
gpg --no-default-keyring --keyring ./admin.gpg --export -a KEYNAME > KEYNAME.asc
```

Delete/Replace endpoints
------------------------

To create a detached signature over the above using itself:

```
gpg --no-default-keyring --keyring ./admin.gpg --detach-sign -a KEYNAME.asc
```

And using a different key:

```
gpg --no-default-keyring --keyring ./admin.gpg --default-key OTHERKEYNAME --detach-sign -a KEYNAME.asc
```

