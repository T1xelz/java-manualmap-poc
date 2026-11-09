plugins {
    application
}

java {
    toolchain.languageVersion.set(JavaLanguageVersion.of(21))
}

dependencies {
    implementation(project(":library"))
}

application {
    mainClass.set("org.t1xel.Main")
    applicationName = "ManualMap"
}

base {
    archivesName.set("ManualMap")
}
