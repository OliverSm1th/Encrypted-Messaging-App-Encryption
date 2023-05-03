# Encrypted Messaging App
The encryption part of my NEA Project<br>
Includes:
* Diffie Hellman Key Exchange (generating a shared secret key)
* AES Encryption/Decryption (using a secret key to encrypt/decrypt messages)
  * ECB Mode- encrypts each block individually (insecure)
  * CBC Mode- uses an initialization vector to introduce a randomness into the algorithm and chains the blocks together ([more info](https://www.highgo.ca/2019/08/08/the-difference-in-five-modes-in-the-aes-encryption-algorithm/)) 
* Tests for both of the algorithms above, making use of official tests to ensure the algorithms are correct

(Updated as part of my PDP to add a CBC encryption/decryption mode and to make it more readable)  
<details>
<summary><b>Example Demonstraction</b></summary>
<img height="400" src="https://i.imgur.com/aykDU1X.gif">
</details>
