# WPCI
White paper continuous deployment system

If you just need to render a latex repo then you can go to (this option cant render private repos):
```bash
https://latex-ci.herokuapp.com/api/v1/renderurl?url=<GIT OR OVERLEAF URL FOR THE REPO>&maintex=<MAIN TEX FILE>
```
To test it first you need to create a user with:
```bash
curl -X POST \
  http://latex-ci.herokuapp.com/api/v1/auth/signin \
  -d '{"username":"youruser@yourcompany.com","password":"password"}'
  ```
then to login and get a TOKEN to post to the endpoint run the following:
```bash
  curl -X POST \
  http://latex-ci.herokuapp.com/api/v1/auth/login \
  -H 'Authorization: Bearer <TOKEN>' \
  -d '{"username":"youruser@yourcompany.com","password":"password"}'
```
and finally you can post a url and recieve an email in your user email with the pdf rendered from your repository:
```bash
  curl -X POST \
  http://latex-ci.herokuapp.com/api/v1/renderrepohash \
  -H 'Authorization: Bearer <TOKEN>' \
  -d '{"remote_url":"<URL FROM GITHUB OR OVERLEAF>", "main_tex":"main.tex"}'
```
