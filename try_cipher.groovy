
import java.security.Key
import javax.crypto.SecretKey
import javax.crypto.KeyGenerator
import java.security.KeyPair
import java.security.KeyPairGenerator
import javax.crypto.Cipher

SecretKey newSecretKey(String algorithm) {
    KeyGenerator.getInstance(algorithm).generateKey()
}

KeyPair newKeyPair(String algorithm) {
    KeyPairGenerator.getInstance(algorithm).generateKeyPair()
}

byte[] encrypt(Key key, byte[] plaintext) throws Exception {
    return Cipher.getInstance(key.algorithm).with {
        init Cipher.ENCRYPT_MODE, key
        doFinal plaintext
    }
}

byte[] encrypt(String transformation, Key key, def params, byte[] plaintext) throws Exception {
    return Cipher.getInstance(transformation).with {
        init Cipher.ENCRYPT_MODE, key, params
        doFinal plaintext
    }
}

byte[] decrypt(Key key, byte[] ciphertext) throws Exception {
    Cipher.getInstance(key.algorithm).with {
        init Cipher.DECRYPT_MODE, key
        doFinal ciphertext
    }
}


byte[] decrypt(String transformation, Key key, def params, byte[] ciphertext) throws Exception {
    Cipher.getInstance(transformation).with {
        init Cipher.DECRYPT_MODE, key, params
        doFinal ciphertext
    }
}

def printKey(Key key, String title) {
    key.with {
        println """
        ${title}:
            algorithm: $algorithm
            format: $format
            encoded: $encoded
            encoded.class: ${encoded.class}
        """.stripIndent()
    }
}

Map encryptAndDecrypt(Key encryptKey, Key decryptKey, byte[] plaintext) {
    def result = [:]
    result.encryptKey = encryptKey
    result.decryptKey = decryptKey
    result.plaintext = plaintext
    result.ciphertext = encrypt result.encryptKey, result.plaintext
    result.decrypted = decrypt result.decryptKey, result.ciphertext
    return result
}

Map encryptAndDecrypt(String transformation, Key encryptKey, Key decryptKey, def params, byte[] plaintext) {
    def result = [:]
    result.transformation = transformation
    result.encryptKey = encryptKey
    result.decryptKey = decryptKey
    result.params = params
    result.plaintext = plaintext
    result.ciphertext = encrypt transformation, result.encryptKey, params, result.plaintext
    result.decrypted = decrypt transformation, result.decryptKey, params, result.ciphertext
    return result
}

def tryEncryptAndDecrypt(Key encryptKey, Key decryptKey, String testString) {
    def result = encryptAndDecrypt(encryptKey, decryptKey, testString.bytes)
    result.origin = testString
    result.decryptedTex = new String(result.decrypted)

    println "algorithm: $encryptKey.algorithm\n"
    //println result
    result.each { key, value -> println "${key}:\t ${value}" }
    printKey result.encryptKey, 'encryptKey'
    printKey result.decryptKey, 'decryptKey'
}


println '---------------------'
//def key = newSecretKey 'AES'
//tryEncryptAndDecrypt(key, key, 'Hello World!')
newSecretKey 'AES' with { key -> 1.times { println "--- round $it ---"; tryEncryptAndDecrypt key, key, 'Hello World!' } }

println '---------------------'
newSecretKey 'DES' with { tryEncryptAndDecrypt it, it, 'Hello World!' }

println '---------------------'
import java.security.KeyFactory
import java.security.spec.RSAPublicKeySpec
import java.security.spec.RSAPrivateKeySpec
import java.security.spec.X509EncodedKeySpec
import java.security.spec.PKCS8EncodedKeySpec
newKeyPair 'RSA' with {
    tryEncryptAndDecrypt it.'public', it.'private', 'Hello World!'


    /*println 'show Key:'
    it.'public'.with { println "modulus: ${modulus}\npublicExponent: ${publicExponent}" }
    it.'private'.with { println "modulus: ${modulus}\nprivateExponent: ${privateExponent}" }
    def keyFactory = KeyFactory.getInstance('RSA')
    println '\nshow KeySpec:'
    keyFactory.getKeySpec(it.'public', RSAPublicKeySpec).with { println "modulus: ${modulus}\npublicExponent: ${publicExponent}" }
    keyFactory.getKeySpec(it.'private', RSAPrivateKeySpec).with { println "modulus: ${modulus}\nprivateExponent: ${privateExponent}" }

    new X509EncodedKeySpec(it.'public'.encoded).with {
        println format; println encoded; println it.class
        keyFactory.generatePublic(it).with {
            println "from encoded to Key: $it"
        }
    }
    new PKCS8EncodedKeySpec(it.'private'.encoded).with {
        println format; println encoded; println it.class
        keyFactory.generatePrivate(it).with {
            println "from encoded to Key: $it"
        }
    }*/

    /*println '# Change PublicExponent'
    def changedPublicKey = new RSAPublicKeySpec(it.'public'.modulus+1,  it.'public'.publicExponent)
    changedPublicKey = KeyFactory.getInstance('RSA').generatePublic(changedPublicKey)
    println "changedPublicKey: $changedPublicKey "
    tryEncryptAndDecrypt changedPublicKey, it.'private', 'Hello World!'*/
}




// #################### encrypt image ####################

import groovy.transform.Field
import java.nio.file.Paths
import java.nio.file.Files
import javax.imageio.ImageIO
import java.nio.ByteBuffer


@Field private static final String ORIGIN_IMAGE_FILE = 'origin.png'
@Field private static final String OUTPUT_DIR = 'output'

def encryptImage(String transformation, Key encryptKey, Key decryptKey, def params) {
    def outputDir = Files.createDirectories Paths.get(OUTPUT_DIR, transformation.replaceAll('[^a-zA-Z0-9.-]', '_')) toFile()

    def image = ImageIO.read(new File(ORIGIN_IMAGE_FILE))
    println "width: ${image.width}\nheight: ${image.height}"
    int[] imageInts = new int[image.width * image.height]
    image.getRGB(0, 0, image.width, image.height, imageInts, 0, image.width)
    def buffer = ByteBuffer.allocate(image.width * image.height * 4)
    buffer.asIntBuffer().put(imageInts)

    println 'write before_encrypte.png'
    ImageIO.write(image, "png", new File(outputDir, 'before_encrypte.png'))

    println 'encrypt and decrypt'
    def result = encryptAndDecrypt transformation, encryptKey, decryptKey, params, buffer.array()

    buffer.clear()
    buffer.put(result.ciphertext, 0, buffer.capacity())
    buffer.flip()
    buffer.asIntBuffer().get(imageInts)
    image.setRGB(0, 0, image.width, image.height, imageInts, 0, image.width)
    println 'write encrypted.png'
    ImageIO.write(image, "png", new File(outputDir, 'encrypted.png'))

    buffer.clear()
    buffer.put(result.decrypted, 0, buffer.capacity())
    buffer.flip()
    buffer.asIntBuffer().get(imageInts)
    image.setRGB(0, 0, image.width, image.height, imageInts, 0, image.width)
    println 'write decrypted.png'
    ImageIO.write(image, "png", new File(outputDir, 'decrypted.png'))
}

import javax.crypto.spec.IvParameterSpec
import javax.crypto.spec.GCMParameterSpec

println '---------------------'
println 'encrypt image\n'

newSecretKey('AES').with {
    encryptImage 'AES', it, it, null
    encryptImage 'AES/ECB/PKCS5Padding', it, it, null
    // javax.crypto.IllegalBlockSizeException: Input length not multiple of 16 bytes
    //encryptImage 'AES/ECB/NoPadding', it, it, null
    //encryptImage 'AES/CBC/NoPadding', it, it, new IvParameterSpec([0] * 16 as byte[])
    encryptImage 'AES/CBC/PKCS5Padding', it, it, new IvParameterSpec([0] * 16 as byte[])
    encryptImage 'AES/GCM/NoPadding', it, it, new GCMParameterSpec(128, [0] * 16 as byte[])
}

System.gc()
