import java.security.Security

Security.providers.each { provider ->
    println "----- Provider -----"
    println "name: ${provider.getName()}"
    println "info: ${provider.getInfo()}"
    println "class: ${provider.getClass()}"
    println " ---------- Service -----------"
    provider.getServices().each { service ->
        println "{$service.algorithm <==> $service.type <==> $service.className"
    }
}

println Security.getAlgorithms("Signature")
println Security.getAlgorithms("MessageDigest")
println Security.getAlgorithms("Cipher")
println Security.getAlgorithms("Mac")
println Security.getAlgorithms("KeyStore")

true
