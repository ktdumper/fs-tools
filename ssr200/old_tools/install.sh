#!/bin/bash

set -e

cd "$(dirname "$0")"
mkdir -p site-packages
pip install pyfatfs==1.1.0 -t site-packages --no-user
patch -u site-packages/pyfatfs/PyFat.py < pyfatfs.diff

echo "Installation completed successfully. If you want to reinstall the module, please delete the site-packages directory first and then proceed with the installation."