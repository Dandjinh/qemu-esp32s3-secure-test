```bash
python $IDF_PATH/tools/idf_tools.py install qemu-xtensa
idf.py set-target esp32-s3
idf.py build
./qemu/run.sh
```
