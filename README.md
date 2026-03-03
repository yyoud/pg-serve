<h1 align="center">
    pg-serve
</h1>


<div align="center">
  <img src="docs/images/pg-serve_logo.svg" alt="pg-serve logo" height="300"/>
</div>


PG-Serve is a crypto-security focused python server API that recieves input via HTTP/JSON, and interacts with a PosrgreSQL database.

---

## Features
- KEK derivation from passwords
- DEK envelope wrapping
- Per-column data encryption envelope
- Session management

## Goal
This project is a proof-of-concept to learn how servers, databases, and secure pipelines really work.
It’s a work in progress - code is not finished yet, but I’m constantly developing and improving it.

Goal: finish baseline development by June.

## Licence
This project is licenced under the [MIT licence](LICENCE).

---

![pg-serve app flow diagram](/docs/images/pg-serve_app_diagram.png)
