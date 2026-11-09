plugins {
    `java-library`
    `maven-publish`
}

java {
    toolchain.languageVersion.set(JavaLanguageVersion.of(21))
    withSourcesJar()
}

base {
    archivesName.set("manualmap")
}

val tools by sourceSets.creating {
    compileClasspath += sourceSets.main.get().output.classesDirs
    runtimeClasspath += sourceSets.main.get().output.classesDirs
}

val integrationTest by sourceSets.creating {
    compileClasspath += sourceSets.main.get().output
    runtimeClasspath += sourceSets.main.get().output
}

configurations[integrationTest.implementationConfigurationName].extendsFrom(configurations.testImplementation.get())
configurations[integrationTest.runtimeOnlyConfigurationName].extendsFrom(configurations.testRuntimeOnly.get())

dependencies {
    val jnaVersion = "5.19.1"
    implementation("net.java.dev.jna:jna:$jnaVersion")
    implementation("net.java.dev.jna:jna-platform:$jnaVersion")

    testImplementation(platform("org.junit:junit-bom:5.10.0"))
    testImplementation("org.junit.jupiter:junit-jupiter")
    testRuntimeOnly("org.junit.platform:junit-platform-launcher")
    testImplementation(tools.output)
}

tasks.withType<JavaCompile>().configureEach {
    options.encoding = "UTF-8"
}

tasks.withType<Test>().configureEach {
    useJUnitPlatform()
    workingDir(projectDir)
}

val shellcode by tasks.registering(JavaExec::class) {
    group = "build"
    description = "Compiles native loaders and generates library resources."
    classpath = tools.runtimeClasspath
    mainClass.set("org.t1xel.tools.ShellcodeTool")
    args("build", projectDir.absolutePath)
    inputs.files(fileTree("src/main/cpp"))
    inputs.property("vcvars64", providers.environmentVariable("MANUALMAP_VCVARS64").orElse(""))
    inputs.property("vcvars32", providers.environmentVariable("MANUALMAP_VCVARS32").orElse(""))
    outputs.dir(layout.buildDirectory.dir("generated-shellcode"))
    outputs.files("build/native/loader64.exe", "build/native/loader32.exe")
}

sourceSets.main {
    resources.srcDir(shellcode.map { layout.buildDirectory.dir("generated-shellcode").get() })
    resources.exclude("*.java.txt")
}

tasks.named("sourcesJar") {
    dependsOn(shellcode)
}

val fixtures by tasks.registering(JavaExec::class) {
    group = "verification"
    description = "Compiles disposable native test hosts and fixtures."
    classpath = tools.runtimeClasspath
    mainClass.set("org.t1xel.tools.ShellcodeTool")
    args("fixtures", projectDir.absolutePath)
    inputs.files(fileTree("src/test/cpp"))
    // Always rebuild: MSVC/SDK discovery can change outside Gradle's inputs.
}

tasks.register<Test>("integrationTest") {
    description = "Runs mapping integration tests against disposable hosts."
    group = "verification"
    dependsOn(fixtures)
    testClassesDirs = integrationTest.output.classesDirs
    classpath = integrationTest.runtimeClasspath
    shouldRunAfter(tasks.test)
    systemProperty("manualmap.integration", "true")
}

tasks.register<JavaExec>("converter") {
    description = "Runs the standalone converter; pass arguments with --args."
    group = "build"
    classpath = tools.runtimeClasspath
    mainClass.set("org.t1xel.tools.ShellcodeTool")
    workingDir(rootProject.projectDir)
}

publishing {
    publications {
        create<MavenPublication>("library") {
            from(components["java"])
            artifactId = "manualmap"
        }
    }
}
