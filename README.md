# WPCI
White paper continuous deployment system

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
  http://latex-ci.herokuapp.com/api/v1/renderrepo \
  -H 'Authorization: Bearer <TOKEN>' \
  -d '{"remote_url":"<URL FROM GITHUB OR OVERLEAF>", "main_tex":"main.tex"}'
```

### For Development

Install vagrant, virtualbox, comandline tools, git. Then!

```

$ vagrant up
$ vagrant ssh
$ cd /vagrant/
$ gunicorn app:application --bind=0.0.0.0:8000
```
