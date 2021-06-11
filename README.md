# Titanium Decrypt
Decrypt TitaniumBackup backups

## Usage
### Install requirements

You may already have PyCryptodome installed. If not:
```sh
$ virtualenv -p python3 venv
$ . venv/bin/activate
$ pip install -Ur requirements.txt
```
### Run

Activate the virtualenv, if you need to:
```sh
$ . venv/bin/activate
```
Run the script:
```sh
$ ./tdecrypt.py my-encrypted-backup.tar.gz
```
You will be prompted for your passphrase.

Alternatively, for batch operation you can put your passphrase in an
environment variable:
```sh
$ passphrase='hunter2'
$ find . ! -iname '*.properties' -exec ./tdecrypt.py {} \;
```

## Contributing
Contributions are welcome. I use Google's import order, `python-black` for
formatting, and `flake8` for linting.

## Thanks
This was made massively easier by Christian Egger's lost G+ post about the
format, and by @bhafer's
[archive](https://github.com/bhafer/TitaniumBackupDecrypt/blob/master/README.md)
of the post in their similar PHP project.
