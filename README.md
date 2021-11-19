# CS3700 Project 5: Web Crawler
by Ronan Loughlin

### High level aproach
This web crawler only crawls the site https://fakebook.3700.network/, looking for 5 secret flags formatted as:
```
<h2 class='secret_flag' style="color:red">FLAG: 64-characters-of-random-alphanumerics</h2>
```

It begins by logging in to fakebook at https://fakebook.3700.network/accounts/login/?next=/fakebook/ using the username and password provided from the command line. Usage:
```
$ ./webcrawler [username] [password]
```

This crawler then performs bfs starting from all links on the homepage https://fakebook.3700.network/. 

All HTTP requests are formed and parsed by this crawler without the help on an HTTP library or cookie manager.


### Testing Overview
This webcrawler was tested simply by running it on fakebook repeatedly.