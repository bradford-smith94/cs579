#Daniel Vinakovsky - Class of 2017
#2015S CS579 Lab 1 test script

#!/bin/bash

allpassed=1

echo "Filesize tests assume encrypted file is exactly 32 bytes larger than the plaintext file."
echo "Building project using Makefile..."
make > /dev/null 2>&1
./pv_keygen key.b64 > /dev/null 2>&1


touch blank
sha1blank="$(sha1sum "blank" | awk '{print $1}')"
./pv_encrypt key.b64 blank blank.enc > /dev/null 2>&1
sha1blankenc="$(sha1sum "blank.enc" | awk '{print $1}')"

if [ "$sha1blankenc" != "$sha1blank" ]
then
    echo 'test blank file encrypt passed (1)'
else
    echo 'test blank file encrypt failed (1)'
    allpassed=0
fi

./pv_decrypt key.b64 blank.enc blank.dec > /dev/null 2>&1
sha1blankdec="$(sha1sum "blank.dec" | awk '{print $1}')"

if [ "$sha1blankdec" == "$sha1blank" ]
then
    echo "test blank file decrypt passed (2)"
else
    echo "test blank file decrypt failed (2)"
    allpassed=0
fi

./pv_encrypt key.b64 Makefile Makefile.enc > /dev/null 2>&1
./pv_decrypt key.b64 Makefile.enc Makefile.dec > /dev/null 2>&1
sha1mf="$(sha1sum "Makefile" | awk '{print $1}')"
sha1mfdec="$(sha1sum "Makefile.dec" | awk '{print $1}')"

if [ "$sha1mf" == "$sha1mfdec" ]
then
    echo "test makefile encrypt/decrypt passed (3)"
else
    echo "test makefile encrypt/decrypt failed (3)"
    allpassed=0
fi

echo "1" > 1.txt

./pv_encrypt key.b64 1.txt 1.txt.enc > /dev/null 2>&1
./pv_decrypt key.b64 1.txt.enc 1.txt.dec > /dev/null 2>&1

sha11="$(sha1sum "1.txt" | awk '{print $1}')"
sha11dec="$(sha1sum "1.txt.dec" | awk '{print $1}')"

if [ "$sha11" == "$sha11dec" ]
then
    echo "test one byte file passed (4)"
else
    echo "test one byte file failed (4)"
    allpassed=0
fi

echo "YELLOWSUBMARINE" > ysub.txt

./pv_encrypt key.b64 ysub.txt ysub.txt.enc > /dev/null 2>&1
./pv_decrypt key.b64 ysub.txt.enc ysub.txt.dec > /dev/null 2>&1

sha1ysub="$(sha1sum "ysub.txt" | awk '{print $1}')"
sha1ysubdec="$(sha1sum "ysub.txt.dec" | awk '{print $1}')"

if [ "$sha1ysub" == "$sha1ysubdec" ]
then
    echo "test 16 byte file passed (5)"
else
    echo "test 16 byte file failed (5)"
    allpassed=0
fi

./pv_encrypt key.b64 pv_keygen pv_keygen.enc > /dev/null 2>&1
./pv_decrypt key.b64 pv_keygen.enc pv_keygen.dec > /dev/null 2>&1

sha1kg="$(sha1sum "pv_keygen" | awk '{print $1}')"
sha1kgdec="$(sha1sum "pv_keygen.dec" | awk '{print $1}')"

if [ "$sha1kg" == "$sha1kgdec" ]
then
    echo "test pv_keygen binary file passed (6)"
else
    echo "test pv_keygen binary file failed (6)"
    allpassed=0
fi

fsblank="$(stat -c%s "blank")"
fsblankenc="$(stat -c%s "blank.enc")"
fstest=`echo "$fsblankenc - $fsblank" | bc`


if [ $fstest -eq 32 ]
then
    echo "test enc filesize == ptxt filesize+32 passed (7)"
else
    echo "test enc filesize == ptxt filesize+32 failed (7)"
    allpassed=0
fi

fspvk="$(stat -c%s "pv_keygen")"
fspvke="$(stat -c%s "pv_keygen.enc")"
fstest=`echo "$fspvke - $fspvk" | bc`

if [ $fstest -eq 32 ]
then
    echo "test filesize on binary file passed (8)"
else
    echo "test filesize on binary file failed (8)"
    allpassed=0
fi

fskey="$(stat -c%s "key.b64")"
fstest=`echo "$fskey" | bc`

if [ $fstest -eq 45 ]
then
    echo "test key filesize = 45 bytes passed (9)"
else
    echo "test key filesize = 45 bytes failed (9)"
    allpassed=0
fi

./pv_encrypt key.b64 Makefile.enc Makefile.enc2 > /dev/null 2>&1
./pv_decrypt key.b64 Makefile.enc2 Makefile.dec1 > /dev/null 2>&1
./pv_decrypt key.b64 Makefile.dec1 Makefile.dec > /dev/null 2>&1

sha1mfdec="$(sha1sum "Makefile.dec" | awk '{print $1}')"

if [ "$sha1mf" == "$sha1mfdec" ]
then
    echo "test double encrypt/decrypt passed (10)"
else
    echo "test double encrypt/decrypt failed (10)"
    allpassed=0
fi

./pv_keygen key.b64 > /dev/null 2>&1

./pv_decrypt key.b64 Makefile.enc Makefile.fail > /dev/null 2>&1

fsmff="$(stat -c%s "Makefile.fail")"
fstest=`echo "$fsmff" | bc`

if [ $fstest -eq 0 ]
then
    echo "test bad decrypt passed (11)"
else
    echo "test bad decrypt failed (11)"
    allpassed=0
fi

rm Makefile.enc > /dev/null 2>&1
rm Makefile.enc2 > /dev/null 2>&1
./pv_encrypt key.b64 Makefile Makefile.enc > /dev/null 2>&1
./pv_encrypt key.b64 Makefile Makefile.enc2 > /dev/null 2>&1

sha1mf="$(sha1sum "Makefile.enc" | awk '{print $1}')"
sha1mfa="$(sha1sum "Makefile.enc2" | awk '{print $1}')"

if [ "$sha1mf" != "$sha1mfa" ]
then
    echo "test use of random iv passed (12)"
else
    echo "test use of random iv failed (12)"
    allpassed=0
fi

dd if=/dev/urandom of=urandom.img bs=16 count=128 > /dev/null 2>&1
./pv_encrypt key.b64 urandom.img urandom.img.enc
./pv_decrypt key.b64 urandom.img.enc urandom.img.dec

sha1ur="$(sha1sum "urandom.img" | awk '{print $1}')"
sha1urdec="$(sha1sum "urandom.img.dec" | awk '{print $1}')"

if [ "$sha1ur" == "$sha1urdec" ]
then
    echo "test encrypt/decrypt of random bytes file passed (13)"
else
    echo "test encrypt/decrypt of random bytes file failed (13)"
    allpassed=0
fi

if [ $allpassed -eq 1 ]
then
    echo "ALL TESTS PASSED"
fi

echo "cleaning up..."
rm -f key.b64 ysub.txt ysub.txt.enc ysub.txt.dec pv_keygen.enc pv_keygen.dec 1.txt 1.txt.enc 1.txt.dec  > /dev/null 2>&1
rm -f Makefile.enc Makefile.enc2 Makefile.dec1 Makefile.dec Makefile.fail blank blank.enc blank.dec  > /dev/null 2>&1
rm -f urandom.img urandom.img.enc urandom.img.dec > /dev/null 2>&1
make clean  > /dev/null 2>&1

exit 0
