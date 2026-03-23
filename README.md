# RSA Key Info

A Python CLI tool to analyze RSA public keys — display key info, factorize weak keys using Fermat's method, and recover private keys.

> Inspired by the [Breaking RSA](https://tryhackme.com/room/breakrsa) room on TryHackMe.

---

## Features

- Display key size, public exponent, and modulus
- Detect weak keys (< 2048 bits)
- Factorize vulnerable keys using Fermat's method
- Recover and export the private key

## Installation

```bash
git clone https://github.com/adelKhalfaoui/rsa_key_info
cd rsa_key_info
pip install -r requirements.txt
```

## Usage

```bash
python rsa_key_info.py -k <key.pub> [-l] [-m] [-f] [-p] [-a]
```

| Flag | Description |
|------|-------------|
| `-k` | Path to RSA public key file **(required)** |
| `-l` | Display key length |
| `-m` | Display modulus (n) |
| `-f` | Factorize n → p, q using Fermat's method |
| `-p` | Generate private key from factored primes |
| `-a` | Run all of the above |

## Example

```bash
python rsa_key_info.py -k test_key.pub -a
```

A demo key `test_key.pub` is included — a deliberately weak 1024-bit RSA key with p and q close together, making it factorable in milliseconds.

## How it works

Fermat's factorization exploits RSA keys where the two prime factors `p` and `q` are close in value. When that's the case, `n ≈ p²`, and `p` can be found by searching near `√n`. This is fast against weak keys but fails against properly generated ones.

## Project Structure

```
rsa_key_info/
├── rsa_key_info.py   # main script
├── test_key.pub      # demo weak RSA key
├── requirements.txt
├── LICENSE
└── README.md
```

## License

MIT — see [LICENSE](LICENSE)
