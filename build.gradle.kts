plugins {
    id("java")
    application
}

group = "org.t1xel"
version = "1.0"

repositories {
    mavenCentral()
}

dependencies {
    testImplementation(platform("org.junit:junit-bom:5.10.0"))
    testImplementation("org.junit.jupiter:junit-jupiter")
    testRuntimeOnly("org.junit.platform:junit-platform-launcher")
    implementation("net.java.dev.jna:jna:5.19.1")
    implementation("net.java.dev.jna:jna-platform:5.19.1")
}

tasks.test {
    useJUnitPlatform()
}

java {
    toolchain.languageVersion.set(JavaLanguageVersion.of(21))
}

application {
    mainClass.set("org.t1xel.Main")
}

val shellcode by tasks.registering(JavaExec::class) {
    dependsOn(tasks.compileJava)
    classpath = files(tasks.compileJava.flatMap { it.destinationDirectory }) + configurations.runtimeClasspath.get()
    mainClass.set("org.t1xel.tools.ShellcodeTool")
    args("build", projectDir.absolutePath)
    inputs.file("native/loader.cpp")
    outputs.dir(layout.buildDirectory.dir("generated-shellcode"))
}

sourceSets.main {
    resources.srcDir(layout.buildDirectory.dir("generated-shellcode"))
}

tasks.processResources {
    dependsOn(shellcode)
}

tasks.register<JavaExec>("fixtures") {
    dependsOn(tasks.compileJava)
    classpath = files(tasks.compileJava.flatMap { it.destinationDirectory }) + configurations.runtimeClasspath.get()
    mainClass.set("org.t1xel.tools.ShellcodeTool")
    args("fixtures", projectDir.absolutePath)
}

tasks.register<Test>("integrationTest") {
    description = "Maps the included native DLL into the included disposable host."
    dependsOn("fixtures", tasks.testClasses)
    testClassesDirs = sourceSets.test.get().output.classesDirs
    classpath = sourceSets.test.get().runtimeClasspath
    useJUnitPlatform()
    filter.includeTestsMatching("*MappingIntegrationTest")
    systemProperty("manualmap.integration", "true")
}
