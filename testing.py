import subprocess

def get_gpu_info_wmic():
    try:
        output = subprocess.check_output(
            "wmic path Win32_VideoController get Name,AdapterRAM", shell=True
        ).decode()
        print("GPU Info (via WMIC):")
        print(output)

        temp_output = subprocess.check_output(
            "wmic /namespace:\\\\root\\wmi PATH MSAcpi_ThermalZoneTemperature get CurrentTemperature", shell=True
        ).decode()
        print("Approximate GPU Temperature (raw ACPI, not always GPU):")
        print(temp_output)

    except Exception as e:
        print(f"Error: {e}")

get_gpu_info_wmic()
