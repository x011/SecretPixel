### hide:

```
python secret_pixel.py hide examples/example.png secret.txt mypublickey.pem examples/example_secret.png
python secret_pixel.py hide examples/example.bmp secret.txt mypublickey.pem examples/example_secret.bmp 
python secret_pixel.py hide examples/example.tif secret.txt mypublickey.pem examples/example_secret.tif
python secret_pixel.py hide examples/example.tga secret.txt mypublickey.pem examples/example_secret.tga
```

## extract:
 
```
python secret_pixel.py extract examples/example_secret.png myprivatekey.pem examples/secret_png.txt
python secret_pixel.py extract examples/example_secret.bmp myprivatekey.pem examples/secret_bmp.txt
python secret_pixel.py extract examples/example_secret.tif myprivatekey.pem examples/secret_tif.txt 
python secret_pixel.py extract examples/example_secret.tga myprivatekey.pem examples/secret_tga.txt
```
