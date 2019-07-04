# check-cve

The tool is utiled to obtain all cve related to specific product, version and other information.

## Run

```
python3 check_cve.py -V gitlab -p gitlab -v 11.8.0 -e community
```

## Options

```
-V --vendor : specify the vendor
-p --product : specify the product
-v --version : specify the version
-e --edition: specify the edition
-o --output : specify the output format: json or csv, if not set, csv by default
```
