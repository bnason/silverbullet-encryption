function arrayBufferToBase64(buffer) {
	const bytes = new Uint8Array(buffer)
	const len = bytes.byteLength

	let binary = ''
	for (let i = 0; i < len; i++) {
		binary += String.fromCharCode(bytes[i])
	}

	return btoa(binary)
}

function base64ToArrayBuffer(base64) {
	var binary_string = atob(base64)
	var len = binary_string.length
	var bytes = new Uint8Array(len)

	for (var i = 0; i < len; i++) {
		bytes[i] = binary_string.charCodeAt(i)
	}

	return bytes.buffer
}

const hashpass = async (pass) => {
	const encodedPass = new TextEncoder('utf-8').encode(pass)
	const hashedPass = await crypto.subtle.digest('SHA-256', encodedPass)

	return hashedPass
}

const encryptSymmetric = async (plaintext, keyBuffer) => {
	// create a random 96-bit initialization vector (IV)
	const iv = crypto.getRandomValues(new Uint8Array(12))

	// encode the text you want to encrypt
	const encodedPlaintext = new TextEncoder().encode(plaintext)

	const secretKey = await crypto.subtle.importKey(
		'raw',
		keyBuffer,
		{
			name: 'AES-GCM',
			length: 256,
		},
		true,
		['encrypt', 'decrypt']
	)

	// encrypt the text with the secret key
	const ciphertext = await crypto.subtle.encrypt(
		{
			name: 'AES-GCM',
			iv,
		},
		secretKey,
		encodedPlaintext
	)

	// return the encrypted text "ciphertext" and the IV
	// encoded in base64
	return {
		ciphertext: arrayBufferToBase64(ciphertext),
		iv: arrayBufferToBase64(iv),
	}
}

const decryptSymmetric = async (ciphertext, iv, key) => {
	// prepare the secret key
	const secretKey = await crypto.subtle.importKey(
		'raw',
		key,
		{
			name: 'AES-GCM',
			length: 256,
		},
		true,
		['encrypt', 'decrypt']
	)

	// decrypt the encrypted text "ciphertext" with the secret key and IV
	const cleartext = await crypto.subtle.decrypt(
		{
			name: 'AES-GCM',
			iv: base64ToArrayBuffer(iv),
		},
		secretKey,
		base64ToArrayBuffer(ciphertext)
	)

	// decode the text and return it
	return new TextDecoder().decode(cleartext)
}

export async function encrypt(text, password) {
	const key = await hashpass(password)

	const { ciphertext, iv } = await encryptSymmetric(text, key)

	return ciphertext + ' ' + iv
}

export async function decrypt(ciphertext, iv, password) {
	const key = await hashpass(password)

	const plaintext = await decryptSymmetric(ciphertext, iv, key)
	return plaintext
}
