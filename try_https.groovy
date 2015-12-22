
def tryConnection = {
    println it
    connect()
    println contentType
    println contentLength
    println contentEncoding
    println new Date(date)
    println new Date(lastModified)
    println()
}

new URL('https://www.baidu.com/').openConnection().with(tryConnection)

new URL('https://bing.com/').openConnection().with(tryConnection)

new URL('https://baijie.cf/').openConnection().with(tryConnection)

import javax.net.ssl.SSLContext
import javax.net.ssl.TrustManager

def sslContext = SSLContext.getInstance('TLSv1.2')
sslContext.init(null, [new NullX509TrustManager()] as TrustManager[], null)

new URL('https://bbs.sumisora.org/').openConnection().with {
    SSLSocketFactory = sslContext.socketFactory
    //hostnameVerifier = {true}
    return it
}.with(tryConnection)

new URL('https://baijie.gq/').openConnection().with {
    SSLSocketFactory = sslContext.socketFactory
    //hostnameVerifier = {true}
    return it
}.with(tryConnection)

import javax.net.ssl.X509TrustManager
import java.security.cert.X509Certificate

class NullX509TrustManager implements X509TrustManager {
    void checkClientTrusted(X509Certificate[] chain, String authType) {
        println "checkClientTrusted($chain, $authType)"
    }
    void checkServerTrusted(X509Certificate[] chain, String authType) {
        println "checkServerTrusted($chain, $authType)"
    }
    X509Certificate[] getAcceptedIssuers() {
        return []
    }
}
