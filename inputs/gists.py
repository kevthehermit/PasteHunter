# ToDo:
'''
Just some notes for reference while i have them

https://developer.github.com/v3/rate_limit/
GET /rate_limit # Doesnt count against your rate limit

{
  "resources": {
    "core": {
      "limit": 5000,
      "remaining": 4999,
      "reset": 1372700873
    },
    "search": {
      "limit": 30,
      "remaining": 18,
      "reset": 1372697452
    }
  },
  "rate": {
    "limit": 5000,
    "remaining": 4999,
    "reset": 1372700873
  }
}


https://developer.github.com/v3/gists/#list-all-public-gists


GET /gists/public

Github API only returns 1Mb of data per gist. look for "truncated"
You will need to get the raw_gist to get full file. If its over 10Mb you need to clone the gist.

Each gist can hold multiple files


Get a single gist

GET /gists/:id





'''