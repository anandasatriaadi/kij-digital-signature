# PDF Digital Signature

|       NRP      |            NAMA            |
|----------------|----------------------------|
| 05111940000050 | Erki Kadhafi Rosyid        |
| 05111940000105 | I Kadek Agus Ariesta Putra |
| 05111940000113 | Putu Ananda Satria Adi     |
| 05111940000161 | Timotius Wirawan           |


## Preparation

### Generate key pair

Generate Private Key
```    
openssl genrsa -out private.pem 1024
```

Generate Public Key
```
openssl rsa -in private.pem -pubout -out public.pem
```

## Installation
```
python3 -m pip install -r requirements
```

## Usage
```
python3 digital_sign.py
```
![Usage](img/usage.png)