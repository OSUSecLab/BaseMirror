// to get filename
// pgrep rild // get <PID>
// ls -l /proc/<PID>>/fd

// Compile with:
// aarch64-linux-android23-clang -fPIE -pie -ldl -o test_cmd{,.c}
#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <string.h>

#define MAX_BYTE_DATA_SIZE 2048
char filename[] = "/dev/umts_ipc0"; // or /dev/umts_ipc1

int main() {
    int fd;

    // Open the file containing hexadecimal data
    FILE *hex_file = fopen("/data/local/tmp/hex_data.txt", "r");
    if (hex_file == NULL) {
        printf("Error opening hexadecimal data file.\n");
        return 1;
    }

    // Read hexadecimal data from file
    char hex_string[MAX_BYTE_DATA_SIZE];
    if (fgets(hex_string, sizeof(hex_string), hex_file) == NULL) {
        printf("Error reading hexadecimal data from file.\n");
        fclose(hex_file);
        return 1;
    }

    fclose(hex_file);

    // Convert hexadecimal string to byte data
    unsigned char byte_data[MAX_BYTE_DATA_SIZE / 2];  // Assuming each byte is represented by 2 characters in the input file
    char *token;
    int counter = 0;
    token = strtok(hex_string, ", ");
    while (token != NULL) {
        sscanf(token, "%hhx", &byte_data[counter++]);
        token = strtok(NULL, ", ");
    }

    // unsigned char byte_data[] = {0x09, 0x00, 0x2e, 0x00, 0x01, 0x07, 0x01, 0x01, 0x00}; 

    fd = open(filename, O_WRONLY | O_CREAT | O_TRUNC, 0666);
    if (fd == -1) {
        printf("Error opening file.\n");
        return 1;
    }

    if (write(fd, byte_data, sizeof(byte_data)) == -1) {
        printf("Error writing to file.\n");
        close(fd);
        return 1;
    }

    close(fd);

    printf("Data written to file successfully.\n");

    return 0;
}
