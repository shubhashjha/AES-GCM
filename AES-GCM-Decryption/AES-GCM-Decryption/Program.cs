﻿// Usage example
using AES_GCM_Decryption;

string encryptedData = "x+BiPifavWY18PebDne+jhIcfICplsdoHLJuEfmvZsofF3IhTEiGU88qbaiknna7i1j3MuqrXPz7vrTPdM6UQd3g99cXj7rye/Urlx1/crj+4Y0OwNzNLiezxnAVbqGhvnFGCHHPXdx9wB13TiCAo8E68r+II0t0Vah6oRpNXkYoNRWx48E8pfdLuF6+Xp13ODXyETcXkxlKfN8BvSHZg2mWQEVAMOYib9oFk/mUk0JjHGE1+AkfPPafAPdiO0k1jiyyuXrQFRrGH8zkoExSkceTzO/eRnlEN2G8ZoHfqECzMmTaJ2EBvvWMPMYBnSMZw80Os5vr3pEc6VPB7QzLYMWr6Hig2EYg4MCEw++Rgqfx/xskAxCpMhx62AnJes/O1LdGWtZi9f0ligsbg17SL2U6j2DNbu8C7p+Go6a2S9mx+7GbzUWEML+mStLJrmpvY/xfgVSW5Zr7rDqIOWh+zTPUpocIQ0a3AbwppD60Me8t4jEIJ/NEk9XSd9qMJFPIAH4SVizQRLt76CqHvmpgQ99Yd0S7Wd5jAqTGLbkvQnMANfbmQndw90sG7AiEOpM8nMoJUQyo73Yv7Vn4+uB2Y4YZSbT59Xlsl7MADEja3S3s+Dk6a/pLd+EpRnOJOuqn3Jmz2+/ZwowSkewPI6ThE4Xf4dL7D1kb0wRZqjwQs1k+xaYOYgkQdS4WTYhHP1KxXSnG36v0nNlijbKMUXhLYvJ4EHEZVyaPHLiU7u+ihrA/CdnJkMi5+sSWAYV5Bdn1fjIzQh5awJyjAVYo7L76BhtZJZkNKK9MN7ywoUTr6wizYileuhVbjTvv+jONfDd6OzpOTS7S35vluWekP/Llv+05LJ3fmHY7zx0guQA/VtjorehBtPjWWOT2OiRZebrufI9E9C5Ni5lFHmGE1FRZQ4DYke3YSlv8Ioe3XGpUQy209WXw4P7zHsAUxmsBL5wD/ILwj/rjgq4A1XEQfOq4S/SL3yMmxAP1bXNBmxLBxcUkbHrN6PukAyOkaGxDbSMSN2IaE/hGTy/C9qseiHlYMV++DhBsSJGJuKS/Tk7VN4VZA3elO6QgKRWRYb6wwGHFJuyy6VsNDnL+6MMJXtQSuB+IJuZk3Jk1gpVauw8JmiIrFhOPmiGdNmpBWO84eJC2IC695Gq6azvBUX+XUvchgcx9zhItXrpD/rSP+kQLw1n/P1EfqD+4VttWBFaiFXeAtKyi9wg7TpkJZcUmBOFMqepO2auq69KpWlGTX6NPEMO0RFbqjopDwDef9wqakXx3sPEiyxn4dSXdur44oi6a4G9RCqrXJrqQ7JIJiJtzNohwtFM2gsYxQMu1m52q9RV74uqjIvWh7EIJoxAkGvBdfPPBOC/IabEpahcLvB0M2ZUWBCBRRfNobwH90pfTWBSWkcG7IeRIL3Kh2XCwIca0PZ5Jzp8nDWvdsjrd+Hj3/93nqHdTwSKwOFqgV7coIE6C4ukhgfwBcYgVjDBqpMJ3qz2fewRdSvKKc0Nko0jGrDZCuDLLTpoH9YUBX/exGSCpwJB7a1h84/S5q8Kw75TZWyqNuu1a5W++vDjWsgFo";
//string key = "6jah1TjcsKC3XXsCWxUVZtOR4rLoDSkB/nn+WY7/5nk=";
//string nonce = "f4jl9iLwWA4Boas0";
string key = "6jah1TjcsKC3XXsCWxUVZtOR4rLoDSkB/nn+WY7/5nk=";
string nonce = "f4jl9iLwWA4Boas0";

string decryptedData = AESGCMHelper.Decrypt(encryptedData, key, nonce);
Console.WriteLine("Decrypted Data: " + decryptedData);