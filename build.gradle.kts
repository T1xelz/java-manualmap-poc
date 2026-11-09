plugins {
    base
}

allprojects {
    group = "org.t1xel"
    version = "1.0"
}

subprojects {
    repositories {
        mavenCentral()
    }
}

tasks.named("build") {
    dependsOn(":library:build", ":cli:build")
}

tasks.named("check") {
    dependsOn(":library:check", ":cli:check")
}

tasks.named("clean") {
    dependsOn(":library:clean", ":cli:clean")
}
