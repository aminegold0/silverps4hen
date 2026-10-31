# BDMV Web Project

## Run

```sh
python3 -m http.server 8080
```

Open `http://127.0.0.1:8080/`.

## Contents

- `index.html`
- `style.css`
- `app.js`
- `assets/00000.mp4`
- `assets/00000.m2ts`
- `assets/bonk/` — extracted binary resources

A browser cannot execute the original BD-J Java/Xlet classes or privileged PS4
operations simply by changing the files to `.html`. A true functional port
requires rewriting those operations for browser APIs.
