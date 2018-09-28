#!/bin/bash
rm -rf docs/
jazzy -c \
-a Kcat \
-u https://imkcat.com \
-g https://github.com/ImKcat/CatCrypto \
-r https://imkcat.github.io/CatCrypto/ \
-m CatCrypto \
--module-version 0.2.3 \
-x -workspace,CatCrypto.xcworkspace,-scheme,CatCrypto-iOS