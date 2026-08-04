
set(INPUTLEAP_GUI_QT_COMPONENTS Core Widgets Network LinguistTools)
if(INPUTLEAP_BUILD_TESTS)
    list(APPEND INPUTLEAP_GUI_QT_COMPONENTS Test)
endif()
find_package (Qt6 ${REQUIRED_QT_VERSION} COMPONENTS ${INPUTLEAP_GUI_QT_COMPONENTS} REQUIRED)

message(STATUS "Using Qt 6")

set (CMAKE_AUTOMOC ON)
set (CMAKE_AUTORCC ON)
set (CMAKE_AUTOUIC ON)
set (CMAKE_INCLUDE_CURRENT_DIR ON)

# files that are used both in tests and the app
set(GUI_COMMON_SOURCE_FILES
    src/Action.cpp
    src/ConfigurationPackageCodec.cpp
    src/ConfigurationPortablePreferences.cpp
    src/ConfigurationRecoveryStore.cpp
    src/ConfigurationPublicSnapshot.cpp
    src/ConfigurationSensitiveEnvelope.cpp
    src/ConfigurationSensitivePayload.cpp
    src/StartupSettingsPreflight.cpp
    src/ConfigurationExportService.cpp
    src/ConfigurationImportPreview.cpp
    src/ConfigurationImportService.cpp
    src/ConfigurationAppTarget.cpp
    src/AppConfigSettingsJournal.cpp
    src/EnvironmentProfileJsonCodec.cpp
    src/CapabilityNegotiationPolicy.cpp
    src/DiagnosticsService.cpp
    src/DiagnosticsRemediationService.cpp
    src/SupportReportBuilder.cpp
    src/EndpointPolicy.cpp
    src/EnvironmentProfile.cpp
    src/EnvironmentProfileController.cpp
    src/EnvironmentProfileIntegrationPolicy.cpp
    src/EnvironmentProfileSelector.cpp
    src/EnvironmentProfileStore.cpp
    src/EnvironmentProfileUiBinding.cpp
    src/CoreConnectionStateController.cpp
    src/DashboardPeerStatePolicy.cpp
    src/DeviceConnectionModel.cpp
    src/DeviceDisplayNameResolver.cpp
    src/DeviceInfo.cpp
    src/DevicePermissions.cpp
    src/DevicePermissionsDialog.cpp
    src/DeviceRegistry.cpp
    src/DiscoveredDevicesModel.cpp
    src/DeviceCard.cpp
    src/DeviceCardDropPolicy.cpp
    src/DeviceDiscoveryPanel.cpp
    src/ProtectionPanel.cpp
    src/ProtocolSecurityPolicy.cpp
    src/Hotkey.cpp
    src/KeySequence.cpp
    src/LocalDeviceIdentity.cpp
    src/LocalMonitorCollector.cpp
    src/NetworkRecoveryPolicy.cpp
    src/NotificationService.cpp
    src/PairingService.cpp
    src/SecureCredentialStore.cpp
    src/PairingProtocolCodec.cpp
    src/PairingController.cpp
    src/ReconnectionPolicy.cpp
    src/TrayMenuPolicy.cpp
    src/UpdateDownloadService.cpp
    src/UpdateHelperProtocol.cpp
    src/UpdateInstallPolicy.cpp
    src/UpdateService.cpp
    src/UpdateTrustConfig.cpp
    src/ZeroconfMetadata.cpp
    src/ZeroconfDiscoveryCoordinator.cpp
)

set(GUI_COMMON_HEADER_FILES
    src/Action.h
    src/ConfigurationPackageCodec.h
    src/ConfigurationPortablePreferences.h
    src/ConfigurationPublicSnapshot.h
    src/ConfigurationSensitiveEnvelope.h
    src/ConfigurationSensitivePayload.h
    src/SensitiveBytes.h
    src/ConfigurationExportService.h
    src/ConfigurationImportPreview.h
    src/ConfigurationImportService.h
    src/ConfigurationAppTarget.h
    src/AppConfigSettingsJournal.h
    src/EnvironmentProfileJsonCodec.h
    src/CapabilityNegotiationPolicy.h
    src/DiagnosticsService.h
    src/DiagnosticsRemediationService.h
    src/SupportReportBuilder.h
    src/EndpointPolicy.h
    src/EnvironmentProfile.h
    src/EnvironmentProfileController.h
    src/EnvironmentProfileIntegrationPolicy.h
    src/EnvironmentProfileSelector.h
    src/EnvironmentProfileStore.h
    src/EnvironmentProfileUiBinding.h
    src/CoreConnectionStateController.h
    src/DashboardPeerStatePolicy.h
    src/DeviceConnectionModel.h
    src/DeviceDisplayNameResolver.h
    src/DeviceInfo.h
    src/DevicePermissions.h
    src/DevicePermissionsDialog.h
    src/DeviceRegistry.h
    src/DiscoveredDevicesModel.h
    src/DeviceCard.h
    src/DeviceCardDropPolicy.h
    src/DeviceDiscoveryPanel.h
    src/ProtectionPanel.h
    src/ProtocolSecurityPolicy.h
    src/Hotkey.h
    src/KeySequence.h
    src/LocalDeviceIdentity.h
    src/LocalMonitorCollector.h
    src/NetworkRecoveryPolicy.h
    src/NotificationService.h
    src/PairingService.h
    src/UpdateDownloadService.h
    src/UpdateHelperProtocol.h
    src/UpdateInstallPolicy.h
    src/UpdateService.h
    src/UpdateTrustConfig.h
    src/SecureCredentialStore.h
    src/PairingProtocolCodec.h
    src/PairingController.h
    src/ReconnectionPolicy.h
    src/TrayMenuPolicy.h
    src/ZeroconfMetadata.h
    src/ZeroconfDiscoveryCoordinator.h
    src/ZeroconfRegistrationState.h
)

set(GUI_SOURCE_FILES
    src/AboutDialog.cpp
    src/ActionDialog.cpp
    src/AddClientDialog.cpp
    src/AppConfig.cpp
    src/AppLocale.cpp
    src/BaseConfig.cpp
    src/CommandProcess.cpp
    src/ClipboardHistoryDialog.cpp
    src/ClipboardHistoryModel.cpp
    src/ClipboardProtectionPolicy.cpp
    src/DataDownloader.cpp
    src/FingerprintAcceptDialog.cpp
    src/FileTransferController.cpp
    src/ConflictResolutionPolicy.cpp
    src/FileTransferResume.cpp
    src/FileTransferService.cpp
    src/FileTransferWorker.cpp
    src/TransferPerformance.cpp
    src/TransferQueue.cpp
    src/HotkeyDialog.cpp
    src/IpcClient.cpp
    src/Ipc.cpp
    src/IpcReader.cpp
    src/KeySequenceWidget.cpp
    src/LogWindow.cpp
    src/main.cpp
    src/MainWindow.cpp
    src/NetworkRecoveryCoordinator.cpp
    src/PairingWizard.cpp
    src/NewScreenWidget.cpp
    src/QInputLeapApplication.cpp
    src/QUtility.cpp
    src/Screen.cpp
    src/ScreenSettingsDialog.cpp
    src/ScreenSetupModel.cpp
    src/ScreenLayoutEditorWidget.cpp
    src/ScreenSetupView.cpp
    src/ServerConfig.cpp
    src/ServerConfigDialog.cpp
    src/SettingsDialog.cpp
    src/SetupWizard.cpp
    src/SslCertificate.cpp
    src/TrashScreenWidget.cpp
    src/UiTheme.cpp
    src/ZeroconfBrowser.cpp
    src/ZeroconfRegister.cpp
    src/ZeroconfServer.cpp
    src/ZeroconfService.cpp
    src/ZeroconfThread.cpp
)

set(GUI_HEADER_FILES
    src/AboutDialog.h
    src/ActionDialog.h
    src/AddClientDialog.h
    src/AppConfig.h
    src/AppConnectionState.h
    src/AppLocale.h
    src/BaseConfig.h
    src/CommandProcess.h
    src/ClipboardHistoryDialog.h
    src/ClipboardHistoryModel.h
    src/ClipboardProtectionPolicy.h
    src/DataDownloader.h
    src/ElevateMode.h
    src/HotkeyDialog.h
    src/FileTransferService.h
    src/FileTransferResume.h
    src/FileTransferController.h
    src/ConflictResolutionPolicy.h
    src/FileTransferWorker.h
    src/TransferPerformance.h
    src/TransferQueue.h
    src/IpcClient.h
    src/Ipc.h
    src/IpcReader.h
    src/KeySequenceWidget.h
    src/LogWindow.h
    src/MainWindow.h
    src/NetworkRecoveryCoordinator.h
    src/PairingWizard.h
    src/NewScreenWidget.h
    src/ProcessorArch.h
    src/QInputLeapApplication.h
    src/QUtility.h
    src/Screen.h
    src/ScreenSettingsDialog.h
    src/ScreenSetupModel.h
    src/ScreenLayoutEditorWidget.h
    src/ScreenSetupView.h
    src/ServerConfigDialog.h
    src/ServerConfig.h
    src/SettingsDialog.h
    src/SetupWizard.h
    src/SslCertificate.h
    src/TrashScreenWidget.h
    src/UiTheme.h
    src/ZeroconfBrowser.h
    src/ZeroconfRecord.h
    src/ZeroconfRegister.h
    src/ZeroconfServer.h
    src/ZeroconfService.h
    src/ZeroconfThread.h
)

set(GUI_UI_FILES
    src/AboutDialog.ui
    src/ActionDialog.ui
    src/AddClientDialog.ui
    src/FingerprintAcceptDialog.ui
    src/HotkeyDialog.ui
    src/LogWindow.ui
    src/MainWindow.ui
    src/ScreenSettingsDialog.ui
    src/ServerConfigDialog.ui
    src/SettingsDialog.ui
    src/SetupWizard.ui
)

set(TS_FILES
    res/lang/gui_af-ZA.ts
    res/lang/gui_ar.ts
    res/lang/gui_bg-BG.ts
    res/lang/gui_ca-AD.ts
    res/lang/gui_cs-CZ.ts
    res/lang/gui_cy.ts
    res/lang/gui_da.ts
    res/lang/gui_de.ts
    res/lang/gui_es.ts
    res/lang/gui_et-EE.ts
    res/lang/gui_fi.ts
    res/lang/gui_fr.ts
    res/lang/gui_gl.ts
    res/lang/gui_grk.ts
    res/lang/gui_he.ts
    res/lang/gui_hi.ts
    res/lang/gui_hr-HR.ts
    res/lang/gui_hu-HU.ts
    res/lang/gui_id.ts
    res/lang/gui_is-IS.ts
    res/lang/gui_it.ts
    res/lang/gui_ja-JP.ts
    res/lang/gui_ko.ts
    res/lang/gui_lt.ts
    res/lang/gui_lv.ts
    res/lang/gui_mr.ts
    res/lang/gui_nl-NL.ts
    res/lang/gui_no.ts
    res/lang/gui_pes-IR.ts
    res/lang/gui_pl-PL.ts
    res/lang/gui_pt-BR.ts
    res/lang/gui_pt-PT.ts
    res/lang/gui_ro.ts
    res/lang/gui_ru.ts
    res/lang/gui_si.ts
    res/lang/gui_sk-SK.ts
    res/lang/gui_sl-SI.ts
    res/lang/gui_sq-AL.ts
    res/lang/gui_sr.ts
    res/lang/gui_sv.ts
    res/lang/gui_th-TH.ts
    res/lang/gui_tr-TR.ts
    res/lang/gui_uk.ts
    res/lang/gui_ur.ts
    res/lang/gui_vi.ts
    res/lang/gui_zh-CN.ts
    res/lang/gui_zh-TW.ts
)

set_source_files_properties(${TS_FILES} PROPERTIES OUTPUT_LOCATION "${CMAKE_CURRENT_SOURCE_DIR}/res/lang")
qt_add_translation(QM_FILES ${TS_FILES} OPTIONS -silent)

# The following file includes X11 headers that later break Qt headers.
set_source_files_properties("src/DisplayIsValid.cpp" PROPERTIES SKIP_UNITY_BUILD_INCLUSION TRUE)

if (WIN32)
    set (GUI_RC_FILES res/win/InputLeap.rc)
    set_property(SOURCE res/win/InputLeap.rc PROPERTY COMPILE_FLAGS /nologo)
endif()

add_executable (input-leap WIN32
    ${GUI_COMMON_SOURCE_FILES}
    ${GUI_COMMON_HEADER_FILES}
    ${GUI_SOURCE_FILES}
    ${GUI_HEADER_FILES}
    ${GUI_UI_FILES}
    ${GUI_RC_FILES}
    res/InputLeap.qrc
)

include_directories (./src)

target_link_libraries(input-leap
    net
    arch
    base
    io
    Qt6::Core
    Qt6::Widgets
    Qt6::Network
)

target_link_libraries(input-leap OpenSSL::SSL OpenSSL::Crypto)

target_compile_definitions (input-leap PRIVATE -DINPUTLEAP_VERSION_STAGE="${INPUTLEAP_VERSION_STAGE}")
target_compile_definitions (input-leap PRIVATE -DINPUTLEAP_REVISION="${INPUTLEAP_REVISION}")

if(MSVC)
    # Qt 6.4 qanystringview.h emits C4702 with MSVC 14.44 even when its
    # include directory is external. Keep /WX for all other diagnostics.
    target_compile_options(input-leap PRIVATE /wd4702)
endif()

if (BUILD_MSWINDOWS)
    function(inputleap_add_tool_version_resource target original_name internal_name description)
        set(INPUTLEAP_TOOL_ORIGINAL_FILENAME "${original_name}")
        set(INPUTLEAP_TOOL_INTERNAL_NAME "${internal_name}")
        set(INPUTLEAP_TOOL_FILE_DESCRIPTION "${description}")
        set(version_resource "${CMAKE_CURRENT_BINARY_DIR}/${target}-version.rc")
        configure_file(res/win/InputLeapToolVersion.rc.in "${version_resource}" @ONLY)
        target_sources(${target} PRIVATE "${version_resource}")
        set_property(SOURCE "${version_resource}" PROPERTY COMPILE_FLAGS /nologo)
    endfunction()

    include_directories ($ENV{BONJOUR_SDK_HOME}/Include)
    find_library (DNSSD_LIB dnssd.lib
                  HINTS ENV BONJOUR_SDK_HOME
                  PATH_SUFFIXES "Lib/x64")
    set_target_properties (input-leap PROPERTIES LINK_FLAGS "/NODEFAULTLIB:LIBCMT")
    target_link_libraries(input-leap ${DNSSD_LIB})
    target_link_libraries(input-leap ole32 oleaut32 shell32)
    add_executable(input-leap-firewall-helper src/FirewallRemediationHelper.cpp)
    inputleap_add_tool_version_resource(
        input-leap-firewall-helper input-leap-firewall-helper.exe
        input-leap-firewall-helper "InputLeap firewall configuration helper")
    target_link_libraries(input-leap-firewall-helper ole32 oleaut32)
    install(TARGETS input-leap-firewall-helper DESTINATION .)
    add_executable(inputleap-update-helper
        src/UpdateInstallerHelper.cpp
        src/WindowsAuthenticodeVerifier.cpp src/WindowsAuthenticodeVerifier.h
        src/WindowsStagedPackageGuard.cpp src/WindowsStagedPackageGuard.h
        src/UpdateHelperProtocol.cpp src/UpdateHelperProtocol.h
        src/UpdateInstallPolicy.cpp src/UpdateInstallPolicy.h
        src/UpdateService.cpp src/UpdateService.h
        src/UpdateTrustConfig.cpp src/UpdateTrustConfig.h
        src/SecureCredentialStore.cpp src/SecureCredentialStore.h)
    inputleap_add_tool_version_resource(
        inputleap-update-helper inputleap-update-helper.exe
        inputleap-update-helper "InputLeap secure update helper")
    target_include_directories(inputleap-update-helper PRIVATE src)
    target_link_libraries(inputleap-update-helper Qt6::Core Qt6::Network
        OpenSSL::Crypto shell32 advapi32 wintrust crypt32 ${libs})
    if(MSVC)
        # MSVC 19.44 reports C4702 at QtCore/qanystringview.h:76 while
        # optimizing two helper translation units. Keep /W4 /WX for this
        # target and suppress only that external-header false positive.
        target_compile_options(inputleap-update-helper PRIVATE /wd4702)
    endif()
    install(TARGETS inputleap-update-helper DESTINATION .)
endif()
if (BUILD_CARBON)
    find_library(APPSERVICES_LIB ApplicationServices)
    target_link_libraries(input-leap ${APPSERVICES_LIB})
endif()
if (BUILD_XWINDOWS OR BUILD_LIBEI)
    target_link_libraries (input-leap dns_sd Threads::Threads)
endif()

target_link_libraries (input-leap common)

if (${CMAKE_SYSTEM_NAME} MATCHES "Darwin")
    install(TARGETS input-leap DESTINATION ${INPUTLEAP_BUNDLE_BINARY_DIR})
elseif (${CMAKE_SYSTEM_NAME} MATCHES "Linux" OR ${CMAKE_SYSTEM_NAME} MATCHES "BSD")
    install (TARGETS input-leap DESTINATION bin)
elseif(WIN32)
    set(CMAKE_INSTALL_SYSTEM_RUNTIME_DESTINATION .)
    if(${CMAKE_BUILD_TYPE} MATCHES "Debug")
        set(CMAKE_INSTALL_DEBUG_LIBRARIES TRUE)
    endif()
    set(CMAKE_INSTALL_UCRT_LIBRARIES TRUE)
    include(InstallRequiredSystemLibraries)
    add_custom_command(
        TARGET input-leap POST_BUILD
        COMMAND ${CMAKE_COMMAND} -E remove_directory "${CMAKE_BINARY_DIR}/qtDeploy"
        COMMAND ${QT_DEPLOY_TOOL} --no-compiler-runtime --no-system-d3d-compiler
            --dir "${CMAKE_BINARY_DIR}/qtDeploy" $<TARGET_FILE:input-leap>
    )
    install(TARGETS input-leap DESTINATION .)
    install(
        DIRECTORY ${CMAKE_BINARY_DIR}/qtDeploy/
        DESTINATION .
        FILES_MATCHING PATTERN "*.*"
    )
endif()

if(INPUTLEAP_BUILD_TESTS)
    add_executable(configurationpackagetests
        test/ConfigurationPackageCodecTests.cpp
        test/ConfigurationPortablePreferencesTests.cpp
        test/ConfigurationRecoveryStoreTests.cpp
        test/ConfigurationSensitiveEnvelopeTests.cpp
        test/StartupSettingsPreflightTests.cpp
        test/CoreTestMain.cpp
        src/ConfigurationPackageCodec.cpp
        src/ConfigurationPackageCodec.h
        src/ConfigurationPortablePreferences.cpp
        src/ConfigurationPortablePreferences.h
        src/ConfigurationRecoveryStore.cpp
        src/ConfigurationRecoveryStore.h
        src/StartupSettingsPreflight.cpp
        src/StartupSettingsPreflight.h
        src/ConfigurationSensitiveEnvelope.cpp
        src/ConfigurationSensitiveEnvelope.h
        src/ConfigurationSensitivePayload.cpp
        src/ConfigurationSensitivePayload.h
        src/SensitiveBytes.h)
    add_test(NAME configurationpackagetests COMMAND configurationpackagetests
        WORKING_DIRECTORY ${CMAKE_RUNTIME_OUTPUT_DIRECTORY})
    set_tests_properties(configurationpackagetests PROPERTIES LABELS "gui-models;configuration-package")
    target_include_directories(configurationpackagetests PUBLIC ../../ext src)
    target_link_libraries(configurationpackagetests gtest gmock Qt6::Core OpenSSL::Crypto ${libs})

    set(MAIN_WINDOW_SESSION_TEST_SOURCES ${GUI_SOURCE_FILES})
    list(REMOVE_ITEM MAIN_WINDOW_SESSION_TEST_SOURCES src/main.cpp)
    add_executable(inputleap-process-fixture-helper
        ../test/helpers/ProcessFixtureHelper.cpp)
    target_include_directories(inputleap-process-fixture-helper PRIVATE src)
    target_link_libraries(inputleap-process-fixture-helper Qt6::Core)
    add_executable(environmentprofilesessiontests
        test/EnvironmentProfileSessionIntegrationTests.cpp
        test/EnvironmentProfileSessionTestMain.cpp
        ${GUI_COMMON_SOURCE_FILES}
        ${GUI_COMMON_HEADER_FILES}
        ${MAIN_WINDOW_SESSION_TEST_SOURCES}
        ${GUI_HEADER_FILES}
        ${GUI_UI_FILES}
        res/InputLeap.qrc)
    add_dependencies(environmentprofilesessiontests inputleap-process-fixture-helper)
    target_compile_definitions(environmentprofilesessiontests PRIVATE
        INPUTLEAP_PROCESS_FIXTURE_HELPER_PATH="$<TARGET_FILE:inputleap-process-fixture-helper>"
        UPDATE_TEST_FIXTURE_DIR="${CMAKE_CURRENT_SOURCE_DIR}/test/fixtures")
    add_test(NAME environmentprofilesessiontests COMMAND environmentprofilesessiontests
        WORKING_DIRECTORY ${CMAKE_RUNTIME_OUTPUT_DIRECTORY})
    set_tests_properties(environmentprofilesessiontests PROPERTIES
        LABELS "gui-models;environment-profiles"
        RESOURCE_LOCK inputleap_global_configuration_locks)
    target_include_directories(environmentprofilesessiontests PUBLIC ../../ext src)
    target_link_libraries(environmentprofilesessiontests gtest gmock net arch base io common
        Qt6::Core Qt6::Widgets Qt6::Network Qt6::Test OpenSSL::SSL OpenSSL::Crypto ${libs})
    if(BUILD_MSWINDOWS)
        set_target_properties(environmentprofilesessiontests PROPERTIES LINK_FLAGS "/NODEFAULTLIB:LIBCMT")
        target_link_libraries(environmentprofilesessiontests ${DNSSD_LIB} ole32 oleaut32 shell32)
    endif()

    add_executable(clipboardhistorytests test/ClipboardHistoryTests.cpp test/GuiTestMain.cpp
            src/ClipboardHistoryModel.cpp src/ClipboardHistoryModel.h
            src/ClipboardHistoryDialog.cpp src/ClipboardHistoryDialog.h
            src/ClipboardProtectionPolicy.cpp src/ClipboardProtectionPolicy.h)
    add_test(NAME clipboardhistorytests COMMAND clipboardhistorytests WORKING_DIRECTORY ${CMAKE_RUNTIME_OUTPUT_DIRECTORY})
    set_tests_properties(clipboardhistorytests PROPERTIES LABELS "gui-models;clipboard-history")
    target_include_directories(clipboardhistorytests PUBLIC ../../ext src)
    target_link_libraries(clipboardhistorytests gtest gmock Qt6::Core Qt6::Gui Qt6::Widgets Qt6::Test ${libs})

    add_executable(clipboardprotectiontests test/ClipboardProtectionTests.cpp test/CoreTestMain.cpp
        src/ClipboardProtectionPolicy.cpp src/ClipboardProtectionPolicy.h)
    add_test(NAME clipboardprotectiontests COMMAND clipboardprotectiontests WORKING_DIRECTORY ${CMAKE_RUNTIME_OUTPUT_DIRECTORY})
    set_tests_properties(clipboardprotectiontests PROPERTIES LABELS "gui-models;clipboard-protection")
    target_include_directories(clipboardprotectiontests PUBLIC ../../ext src)
    target_link_libraries(clipboardprotectiontests gtest gmock Qt6::Core ${libs})

    add_executable(transferperformancetests test/TransferPerformanceTests.cpp test/CoreTestMain.cpp
        src/TransferPerformance.cpp src/TransferPerformance.h)
    add_test(NAME transferperformancetests COMMAND transferperformancetests WORKING_DIRECTORY ${CMAKE_RUNTIME_OUTPUT_DIRECTORY})
    set_tests_properties(transferperformancetests PROPERTIES LABELS "gui-models;file-transfer-performance")
    target_include_directories(transferperformancetests PUBLIC ../../ext src)
    target_link_libraries(transferperformancetests gtest gmock Qt6::Core ${libs})

    add_executable(transferqueuetests test/TransferQueueTests.cpp test/CoreTestMain.cpp
        src/TransferQueue.cpp src/TransferQueue.h)
    add_test(NAME transferqueuetests COMMAND transferqueuetests WORKING_DIRECTORY ${CMAKE_RUNTIME_OUTPUT_DIRECTORY})
    set_tests_properties(transferqueuetests PROPERTIES LABELS "gui-models;file-transfer-queue")
    target_include_directories(transferqueuetests PUBLIC ../../ext src)
    target_link_libraries(transferqueuetests gtest gmock Qt6::Core ${libs})

    add_executable(capabilitynegotiationtests test/CapabilityNegotiationPolicyTests.cpp test/CoreTestMain.cpp
        src/CapabilityNegotiationPolicy.cpp src/CapabilityNegotiationPolicy.h)
    add_test(NAME capabilitynegotiationtests COMMAND capabilitynegotiationtests WORKING_DIRECTORY ${CMAKE_RUNTIME_OUTPUT_DIRECTORY})
    set_tests_properties(capabilitynegotiationtests PROPERTIES LABELS "gui-models;capability-negotiation")
    target_include_directories(capabilitynegotiationtests PUBLIC ../../ext src)
    target_link_libraries(capabilitynegotiationtests gtest gmock Qt6::Core ${libs})

    add_executable(updateservicetests test/UpdateServiceTests.cpp test/CoreTestMain.cpp
        src/UpdateService.cpp src/UpdateService.h
        src/SecureCredentialStore.cpp src/SecureCredentialStore.h
        src/UpdateTrustConfig.cpp src/UpdateTrustConfig.h)
    add_test(NAME updateservicetests COMMAND updateservicetests
        WORKING_DIRECTORY ${CMAKE_RUNTIME_OUTPUT_DIRECTORY})
    set_tests_properties(updateservicetests PROPERTIES LABELS "gui-models;secure-update")
    find_program(INPUTLEAP_PYTHON_EXECUTABLE NAMES python REQUIRED)
    add_test(NAME updatemanifestsignertests
        COMMAND ${INPUTLEAP_PYTHON_EXECUTABLE} -m unittest -v test_update_manifest.py
        WORKING_DIRECTORY ${CMAKE_SOURCE_DIR}/tools)
    set_tests_properties(updatemanifestsignertests PROPERTIES
        LABELS "secure-update;signer")
    target_include_directories(updateservicetests PUBLIC ../../ext src)
    target_compile_definitions(updateservicetests PRIVATE
        UPDATE_TEST_FIXTURE_DIR="${CMAKE_CURRENT_SOURCE_DIR}/test/fixtures")
    target_link_libraries(updateservicetests gtest gmock Qt6::Core Qt6::Network Qt6::Test
        OpenSSL::Crypto ${libs})

    add_executable(updatedownloadservicetests test/UpdateDownloadServiceTests.cpp test/CoreTestMain.cpp
        src/UpdateDownloadService.cpp src/UpdateDownloadService.h
        src/UpdateService.h)
    add_test(NAME updatedownloadservicetests COMMAND updatedownloadservicetests
        WORKING_DIRECTORY ${CMAKE_RUNTIME_OUTPUT_DIRECTORY})
    set_tests_properties(updatedownloadservicetests PROPERTIES LABELS "gui-models;secure-update")
    target_include_directories(updatedownloadservicetests PUBLIC ../../ext src)
    target_link_libraries(updatedownloadservicetests gtest gmock Qt6::Core Qt6::Network Qt6::Test
        OpenSSL::Crypto ${libs})

    add_executable(updateinstallpolicytests test/UpdateInstallPolicyTests.cpp test/CoreTestMain.cpp
        src/UpdateInstallPolicy.cpp src/UpdateInstallPolicy.h
        src/UpdateService.h)
    add_test(NAME updateinstallpolicytests COMMAND updateinstallpolicytests
        WORKING_DIRECTORY ${CMAKE_RUNTIME_OUTPUT_DIRECTORY})
    set_tests_properties(updateinstallpolicytests PROPERTIES LABELS "gui-models;secure-update")
    target_include_directories(updateinstallpolicytests PUBLIC ../../ext src)
    target_link_libraries(updateinstallpolicytests gtest gmock Qt6::Core
        OpenSSL::Crypto ${libs})

    add_executable(updatehelperprotocoltests test/UpdateHelperProtocolTests.cpp test/CoreTestMain.cpp
        src/UpdateHelperProtocol.cpp src/UpdateHelperProtocol.h
        src/UpdateInstallPolicy.cpp src/UpdateInstallPolicy.h
        src/UpdateService.h)
    add_test(NAME updatehelperprotocoltests COMMAND updatehelperprotocoltests
        WORKING_DIRECTORY ${CMAKE_RUNTIME_OUTPUT_DIRECTORY})
    set_tests_properties(updatehelperprotocoltests PROPERTIES LABELS "gui-models;secure-update")
    target_include_directories(updatehelperprotocoltests PUBLIC ../../ext src)
    target_link_libraries(updatehelperprotocoltests gtest gmock Qt6::Core
        OpenSSL::Crypto ${libs})

    if(WIN32)
        add_executable(windowsauthenticodetests
            test/WindowsAuthenticodeVerifierTests.cpp test/CoreTestMain.cpp
            src/WindowsAuthenticodeVerifier.cpp src/WindowsAuthenticodeVerifier.h)
        add_test(NAME windowsauthenticodetests COMMAND windowsauthenticodetests
            WORKING_DIRECTORY ${CMAKE_RUNTIME_OUTPUT_DIRECTORY})
        set_tests_properties(windowsauthenticodetests PROPERTIES
            LABELS "gui-models;secure-update;windows")
        target_include_directories(windowsauthenticodetests PUBLIC ../../ext src)
        target_link_libraries(windowsauthenticodetests gtest gmock Qt6::Core
            wintrust crypt32 ${libs})

        add_executable(windowsstagedpackageguardtests
            test/WindowsStagedPackageGuardTests.cpp test/CoreTestMain.cpp
            src/WindowsStagedPackageGuard.cpp src/WindowsStagedPackageGuard.h)
        add_test(NAME windowsstagedpackageguardtests
            COMMAND windowsstagedpackageguardtests
            WORKING_DIRECTORY ${CMAKE_RUNTIME_OUTPUT_DIRECTORY})
        set_tests_properties(windowsstagedpackageguardtests PROPERTIES
            LABELS "gui-models;secure-update;windows")
        target_include_directories(windowsstagedpackageguardtests PUBLIC ../../ext src)
        target_link_libraries(windowsstagedpackageguardtests gtest gmock Qt6::Core
            ${libs})
    endif()

    add_executable(reconnectionpolicytests test/ReconnectionPolicyTests.cpp test/CoreTestMain.cpp
        src/ReconnectionPolicy.cpp src/ReconnectionPolicy.h)
    add_test(NAME reconnectionpolicytests COMMAND reconnectionpolicytests WORKING_DIRECTORY ${CMAKE_RUNTIME_OUTPUT_DIRECTORY})
    set_tests_properties(reconnectionpolicytests PROPERTIES LABELS "gui-models;reconnection")
    target_include_directories(reconnectionpolicytests PUBLIC ../../ext src)
    target_link_libraries(reconnectionpolicytests gtest gmock Qt6::Core ${libs})

    add_executable(networkrecoverytests test/NetworkRecoveryPolicyTests.cpp test/CoreTestMain.cpp
        src/NetworkRecoveryPolicy.cpp src/NetworkRecoveryPolicy.h)
    add_test(NAME networkrecoverytests COMMAND networkrecoverytests WORKING_DIRECTORY ${CMAKE_RUNTIME_OUTPUT_DIRECTORY})

    add_executable(notificationtests test/NotificationServiceTests.cpp test/CoreTestMain.cpp
        src/NotificationService.cpp src/NotificationService.h)
    add_test(NAME notificationtests COMMAND notificationtests WORKING_DIRECTORY ${CMAKE_RUNTIME_OUTPUT_DIRECTORY})
    set_tests_properties(networkrecoverytests PROPERTIES LABELS "gui-models;network-recovery")
    target_include_directories(networkrecoverytests PUBLIC ../../ext src)
    target_link_libraries(networkrecoverytests gtest gmock Qt6::Core ${libs})
    set_tests_properties(notificationtests PROPERTIES LABELS "gui-models;notifications")
    target_include_directories(notificationtests PUBLIC ../../ext src)
    target_link_libraries(notificationtests gtest gmock Qt6::Core ${libs})

    set(GUI_TEST_SOURCE_FILES
        src/AboutDialog.cpp
        ../lib/common/Version.cpp
        test/DiscoveredDevicesTests.cpp
        test/ConfigurationExportServiceTests.cpp
        test/ConfigurationImportPreviewTests.cpp
        test/ConfigurationImportServiceTests.cpp
        test/ConfigurationAppTargetTests.cpp
        test/AppConfigSettingsJournalTests.cpp
        test/EnvironmentProfileControllerTests.cpp
        test/EnvironmentProfileIntegrationPolicyTests.cpp
        test/EnvironmentProfileJsonCodecTests.cpp
        test/EnvironmentProfileSelectorTests.cpp
        test/ConfigurationPublicSnapshotTests.cpp
        test/EnvironmentProfileTests.cpp
        test/EnvironmentProfileStoreTests.cpp
        test/EnvironmentProfileUiBindingTests.cpp
        test/ServerConfigEnvironmentTests.cpp
        test/DeviceCardDropTests.cpp
        test/DeviceConnectionModelTests.cpp
        test/DashboardPeerStatePolicyTests.cpp
        test/CoreConnectionStateControllerTests.cpp
        test/AboutDialogAccessibilityTests.cpp
        test/DeviceRegistryTests.cpp
        test/DevicePermissionsTests.cpp
        test/FileTransferControllerTests.cpp
        test/FileTransferConflictTests.cpp
        test/FileTransferPolicyTests.cpp
        test/FileTransferResumeTests.cpp
        test/FileTransferServiceTests.cpp
        test/KeySequenceTests.cpp
        test/HotkeyTests.cpp
        test/LocalMonitorCollectorTests.cpp
        test/TrayMenuPolicyTests.cpp
        test/ScreenLayoutTests.cpp
        test/ScreenLayoutEditorTests.cpp
        test/main.cpp
    )

    add_executable(guiunittests
        ${GUI_TEST_SOURCE_FILES}
        ${GUI_COMMON_SOURCE_FILES}
        ${GUI_COMMON_HEADER_FILES}
        src/FileTransferService.cpp
        src/FileTransferService.h
        src/ConflictResolutionPolicy.cpp
        src/ConflictResolutionPolicy.h
        src/FileTransferResume.cpp
        src/FileTransferResume.h
        src/FileTransferController.cpp
        src/FileTransferController.h
        src/FileTransferWorker.cpp
        src/FileTransferWorker.h
        src/TransferPerformance.cpp
        src/TransferPerformance.h
        src/ScreenSetupModel.cpp
        src/ScreenSetupModel.h
        src/ScreenLayoutEditorWidget.cpp
        src/ScreenLayoutEditorWidget.h
        src/Screen.cpp
        src/Screen.h
        src/ServerConfig.cpp
        src/ServerConfig.h
        src/AddClientDialog.cpp
        src/AddClientDialog.h
        src/AddClientDialog.ui
        src/BaseConfig.cpp
        src/BaseConfig.h
        src/AppConfig.cpp
        src/AppConfig.h
    )
    add_dependencies(guiunittests inputleap-process-fixture-helper)
    target_compile_definitions(guiunittests PRIVATE
        INPUTLEAP_FILE_TRANSFER_TEST_HOOKS=1
        INPUTLEAP_PROCESS_FIXTURE_HELPER_PATH="$<TARGET_FILE:inputleap-process-fixture-helper>")
    add_test(NAME guiunittests COMMAND guiunittests WORKING_DIRECTORY ${CMAKE_RUNTIME_OUTPUT_DIRECTORY})
    set_tests_properties(guiunittests PROPERTIES
        RESOURCE_LOCK inputleap_global_configuration_locks)
    target_include_directories(guiunittests PUBLIC ../../ext src)
    target_link_libraries(guiunittests gtest gmock Qt6::Core Qt6::Widgets Qt6::Network Qt6::Test OpenSSL::Crypto ${libs})

    add_executable(guimodeltests
        test/DiscoveredDevicesTests.cpp test/EnvironmentProfileControllerTests.cpp test/EnvironmentProfileIntegrationPolicyTests.cpp test/EnvironmentProfileSelectorTests.cpp test/EnvironmentProfileTests.cpp test/EnvironmentProfileStoreTests.cpp test/EnvironmentProfileUiBindingTests.cpp test/SettingsDialogEnvironmentProfileTests.cpp test/ServerConfigEnvironmentTests.cpp test/DeviceCardDropTests.cpp test/DeviceConnectionModelTests.cpp
        test/DashboardPeerStatePolicyTests.cpp test/CoreConnectionStateControllerTests.cpp
        test/DeviceRegistryTests.cpp test/PairingServiceTests.cpp test/SecureCredentialStoreTests.cpp test/PairingFlowTests.cpp
        test/ZeroconfMetadataTests.cpp test/ScreenLayoutTests.cpp test/ScreenLayoutEditorTests.cpp
        test/LocalMonitorCollectorTests.cpp test/TrayMenuPolicyTests.cpp
        test/GuiTestMain.cpp ${GUI_COMMON_SOURCE_FILES} ${GUI_COMMON_HEADER_FILES}
        src/FileTransferService.cpp src/FileTransferService.h
        src/ConflictResolutionPolicy.cpp src/ConflictResolutionPolicy.h
        src/FileTransferResume.cpp src/FileTransferResume.h
        src/TransferPerformance.cpp src/TransferPerformance.h
        src/PairingWizard.cpp src/PairingWizard.h src/ScreenSetupModel.cpp src/ScreenSetupModel.h
        src/ScreenLayoutEditorWidget.cpp src/ScreenLayoutEditorWidget.h
        src/Screen.cpp src/Screen.h src/ServerConfig.cpp src/ServerConfig.h
        src/AddClientDialog.cpp src/AddClientDialog.h src/AddClientDialog.ui
        src/BaseConfig.cpp src/BaseConfig.h
        src/AppConfig.cpp src/AppConfig.h src/AppLocale.cpp src/AppLocale.h
        src/QUtility.cpp src/QUtility.h src/SettingsDialog.cpp src/SettingsDialog.h src/SettingsDialog.ui)
    add_dependencies(guimodeltests inputleap-process-fixture-helper)
    target_compile_definitions(guimodeltests PRIVATE
        INPUTLEAP_PROCESS_FIXTURE_HELPER_PATH="$<TARGET_FILE:inputleap-process-fixture-helper>"
        PAIRING_TEST_FIXTURE_DIR="${CMAKE_CURRENT_SOURCE_DIR}/test/fixtures"
        PAIRING_SOURCE_DIR="${CMAKE_CURRENT_SOURCE_DIR}/src")
    target_sources(guimodeltests PRIVATE res/InputLeap.qrc)
    add_test(NAME guimodeltests COMMAND guimodeltests WORKING_DIRECTORY ${CMAKE_RUNTIME_OUTPUT_DIRECTORY})
    set_tests_properties(guimodeltests PROPERTIES
        LABELS "gui-models"
        RESOURCE_LOCK inputleap_global_configuration_locks)
    target_include_directories(guimodeltests PUBLIC ../../ext src)
    target_link_libraries(guimodeltests gtest gmock Qt6::Core Qt6::Widgets Qt6::Network Qt6::Test OpenSSL::SSL OpenSSL::Crypto ${libs})

    add_executable(devicepermissionstests
        test/DevicePermissionsTests.cpp test/DevicePermissionsDialogTests.cpp test/DevicePermissionsDialogTestMain.cpp test/ProtectionPanelTests.cpp
        src/DevicePermissions.cpp src/DevicePermissions.h
        src/DevicePermissionsDialog.cpp src/DevicePermissionsDialog.h
        src/ProtectionPanel.cpp src/ProtectionPanel.h
        src/DeviceInfo.cpp src/DeviceInfo.h
        src/DeviceRegistry.cpp src/DeviceRegistry.h)
    add_test(NAME devicepermissionstests COMMAND devicepermissionstests WORKING_DIRECTORY ${CMAKE_RUNTIME_OUTPUT_DIRECTORY})
    set_tests_properties(devicepermissionstests PROPERTIES LABELS "gui-models;device-permissions")
    target_include_directories(devicepermissionstests PUBLIC ../../ext src)
    target_link_libraries(devicepermissionstests gtest gmock Qt6::Core Qt6::Widgets Qt6::Network Qt6::Test)

    add_executable(zeroconfmetadatatests test/ZeroconfMetadataTests.cpp test/CoreTestMain.cpp
        src/CapabilityNegotiationPolicy.cpp src/CapabilityNegotiationPolicy.h
        src/LocalDeviceIdentity.cpp src/LocalDeviceIdentity.h src/ZeroconfMetadata.cpp src/ZeroconfMetadata.h
        src/ZeroconfDiscoveryCoordinator.cpp src/ZeroconfDiscoveryCoordinator.h src/ZeroconfRegistrationState.h)
    add_test(NAME zeroconfmetadatatests COMMAND zeroconfmetadatatests WORKING_DIRECTORY ${CMAKE_RUNTIME_OUTPUT_DIRECTORY})
    set_tests_properties(zeroconfmetadatatests PROPERTIES LABELS "gui-models;zeroconf-metadata")
    target_include_directories(zeroconfmetadatatests PUBLIC ../../ext src)
    target_link_libraries(zeroconfmetadatatests gtest gmock Qt6::Core Qt6::Network Qt6::Test ${libs})

    add_executable(protocolsecuritytests test/ProtocolSecurityPolicyTests.cpp test/CoreTestMain.cpp
        src/ProtocolSecurityPolicy.cpp src/ProtocolSecurityPolicy.h)
    add_test(NAME protocolsecuritytests COMMAND protocolsecuritytests WORKING_DIRECTORY ${CMAKE_RUNTIME_OUTPUT_DIRECTORY})
    set_tests_properties(protocolsecuritytests PROPERTIES LABELS "security;protocol")
    target_include_directories(protocolsecuritytests PUBLIC ../../ext src)
    target_link_libraries(protocolsecuritytests gtest gmock Qt6::Core Qt6::Network Qt6::Test OpenSSL::Crypto ${libs})

    add_executable(ipcreadertests test/IpcReaderTests.cpp src/IpcReader.cpp src/IpcReader.h src/Ipc.cpp src/Ipc.h)
    add_test(NAME ipcreadertests COMMAND ipcreadertests WORKING_DIRECTORY ${CMAKE_RUNTIME_OUTPUT_DIRECTORY})
    set_tests_properties(ipcreadertests PROPERTIES LABELS "gui-models")
    target_include_directories(ipcreadertests PUBLIC src)
    target_link_libraries(ipcreadertests Qt6::Core Qt6::Network Qt6::Test)

    add_executable(ipcclienttests test/IpcClientTests.cpp
        src/IpcClient.cpp src/IpcClient.h src/IpcReader.cpp src/IpcReader.h src/Ipc.cpp src/Ipc.h)
    add_test(NAME ipcclienttests COMMAND ipcclienttests WORKING_DIRECTORY ${CMAKE_RUNTIME_OUTPUT_DIRECTORY})
    set_tests_properties(ipcclienttests PROPERTIES LABELS "gui-models;ipc")
    target_include_directories(ipcclienttests PUBLIC src)
    target_link_libraries(ipcclienttests Qt6::Core Qt6::Network Qt6::Test)

    add_executable(diagnosticstests test/DiagnosticsServiceTests.cpp test/CoreTestMain.cpp
        src/DiagnosticsService.cpp src/DiagnosticsService.h src/EndpointPolicy.cpp src/EndpointPolicy.h)
    add_test(NAME diagnosticstests COMMAND diagnosticstests WORKING_DIRECTORY ${CMAKE_RUNTIME_OUTPUT_DIRECTORY})
    set_tests_properties(diagnosticstests PROPERTIES LABELS "gui-models;diagnostics")
    target_include_directories(diagnosticstests PUBLIC ../../ext src)
    target_link_libraries(diagnosticstests gtest gmock Qt6::Core Qt6::Network Qt6::Test ${libs})

    add_executable(supportreporttests test/SupportReportBuilderTests.cpp test/CoreTestMain.cpp
        src/SupportReportBuilder.cpp src/SupportReportBuilder.h
        src/DiagnosticsService.cpp src/DiagnosticsService.h
        src/EndpointPolicy.cpp src/EndpointPolicy.h
        src/DiagnosticsRemediationService.cpp src/DiagnosticsRemediationService.h)
    add_test(NAME supportreporttests COMMAND supportreporttests WORKING_DIRECTORY ${CMAKE_RUNTIME_OUTPUT_DIRECTORY})
    set_tests_properties(supportreporttests PROPERTIES LABELS "gui-models;diagnostics;support-report")
    target_include_directories(supportreporttests PUBLIC ../../ext src)
    target_link_libraries(supportreporttests gtest gmock Qt6::Core Qt6::Network Qt6::Test ${libs})
    if(WIN32)
        target_link_libraries(supportreporttests ole32 oleaut32 shell32)
    endif()

    add_executable(diagnosticsremediationtests test/DiagnosticsRemediationServiceTests.cpp test/CoreTestMain.cpp
        src/DiagnosticsRemediationService.cpp src/DiagnosticsRemediationService.h)
    add_test(NAME diagnosticsremediationtests COMMAND diagnosticsremediationtests WORKING_DIRECTORY ${CMAKE_RUNTIME_OUTPUT_DIRECTORY})
    set_tests_properties(diagnosticsremediationtests PROPERTIES LABELS "gui-models;diagnostics;remediation")
    target_include_directories(diagnosticsremediationtests PUBLIC ../../ext src)
    target_link_libraries(diagnosticsremediationtests gtest gmock Qt6::Core Qt6::Test ${libs})
    if(WIN32)
        target_link_libraries(diagnosticsremediationtests ole32 oleaut32 shell32)
    endif()
endif()
