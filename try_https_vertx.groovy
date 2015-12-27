//@GrabResolver(name='oschina', root='http://maven.oschina.net/content/groups/public/')
@Grapes([
    @Grab('io.vertx:vertx-core:3.2.0'),
    @Grab('io.vertx:vertx-lang-groovy:3.2.0')
])
@GrabExclude('org.codehaus.groovy:groovy-all')
import io.vertx.groovy.core.Vertx

def vertx = Vertx.vertx()

def options = [
    connectTimeout: 10000,
    ssl: true,
    trustStoreOptions: [
        path: "temprootca"
    ]
]
vertx.createHttpClient(options).get(443, 'baijie.gq', '/') { response ->
    println "Received response with status code ${response.statusCode()}"
    println "Status message is ${response.statusMessage()}"
    response.bodyHandler { totalBuffer ->
        println "Total response body length is ${totalBuffer.length()}"
        //println "Total response body is ${totalBuffer}"
    }
    vertx.close()
    System.gc()
}.exceptionHandler { e ->
    println("Received exception: ${e.getMessage()}")
    e.printStackTrace()
}.end()


println 'over'
