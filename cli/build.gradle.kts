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

distributions {
    main {
        contents {
            from(rootProject.file("LICENSE"), rootProject.file("THIRD_PARTY_NOTICES.md"))
        }
    }
}
