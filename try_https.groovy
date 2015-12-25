// see http://docs.oracle.com/javase/8/docs/technotes/guides/security/jsse/JSSERefGuide.html#InstallationAndCustomization
//System.setProperty 'javax.net.ssl.trustStore', 'temprootca'
//System.setProperty 'javax.net.ssl.trustStore', new File('temprootca').absolutePath.replaceAll('\\\\', '/')
System.setProperty 'javax.net.ssl.trustStore', new File('temprootca').absolutePath
//System.setProperty 'javax.net.ssl.trustStorePassword', 'temppassword'
//System.setProperty 'javax.net.debug', 'true'
println "javax.net.ssl.trustStore: ${System.getProperty('javax.net.ssl.trustStore')}\n"

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

//new URL('https://www.baidu.com/').openConnection().with(tryConnection)

//new URL('https://bing.com/').openConnection().with(tryConnection)

//new URL('https://baijie.cf/').openConnection().with(tryConnection)

new URL('https://bbs.sumisora.org/').openConnection().with(tryConnection)

new URL('https://baijie.gq/').openConnection().with(tryConnection)

//new URL('https://baijie.cf/').openConnection().with(tryConnection)
