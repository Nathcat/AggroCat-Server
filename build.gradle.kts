plugins {
    id("java")
}

group = "org.example"
version = "1.0-SNAPSHOT"

repositories {
    mavenCentral()
}

dependencies {
    testImplementation("org.junit.jupiter:junit-jupiter-api:5.8.1")
    testRuntimeOnly("org.junit.jupiter:junit-jupiter-engine:5.8.1")
    implementation(files("libs/Java-WebSocket-1.5.7.jar"))
    implementation(files("libs/json-simple-1.1.1.jar"))
    implementation(files("libs/RSACryptoSystem.jar"))
}

tasks.getByName<Test>("test") {
    useJUnitPlatform()
}