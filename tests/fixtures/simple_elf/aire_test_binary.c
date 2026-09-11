/* A small, deterministic call-graph fixture. See GROUND_TRUTH.md. */
#include <stdio.h>
#include <string.h>

#define INPUT_CAPACITY 32

unsigned int global_bias = 7;

struct InputData {
    char transformed[INPUT_CAPACITY];
    unsigned int length;
    unsigned int checksum;
    unsigned int transformed_checksum;
};

void print_banner(void)
{
    puts("A.I.R.E. simple ELF fixture");
}

void initialize_app(void)
{
    global_bias = 7;
    print_banner();
}

unsigned int calculate_checksum(const char *text)
{
    unsigned int checksum = 0;
    for (unsigned int i = 0; text[i] != '\0'; ++i) {
        checksum = (checksum + (unsigned char)text[i]) % 256;
    }
    return checksum;
}

int validate_input(const char *text, struct InputData *data)
{
    size_t length = strlen(text);
    if (length == 0 || length >= INPUT_CAPACITY) {
        puts("Input must contain 1 to 31 printable ASCII characters.");
        return 0;
    }
    for (size_t i = 0; i < length; ++i) {
        unsigned char ch = (unsigned char)text[i];
        if (ch < 32 || ch > 126) {
            puts("Input must be printable ASCII.");
            return 0;
        }
    }
    data->length = (unsigned int)length;
    data->checksum = calculate_checksum(text);
    return 1;
}

void transform_input(const char *text, struct InputData *data)
{
    for (unsigned int i = 0; i < data->length; ++i) {
        char ch = text[i];
        if (ch >= 'a' && ch <= 'z') {
            data->transformed[i] = (char)(ch - ('a' - 'A'));
        } else {
            data->transformed[i] = ch;
        }
    }
    data->transformed[data->length] = '\0';
    data->transformed_checksum = calculate_checksum(data->transformed);
}

int process_input(const char *text, struct InputData *data)
{
    if (!validate_input(text, data)) {
        return 0;
    }
    transform_input(text, data);
    return 1;
}

unsigned int add_values(unsigned int left, unsigned int right)
{
    return left + right;
}

unsigned int multiply_values(unsigned int left, unsigned int right)
{
    return left * right;
}

unsigned int secret_operation(const struct InputData *data)
{
    puts("Secret operation selected.");
    return add_values(calculate_checksum(data->transformed), global_bias);
}

unsigned int choose_operation(unsigned int operation, const struct InputData *data)
{
    switch (operation) {
    case 1:
        return add_values(data->transformed_checksum, data->length);
    case 2:
        return multiply_values(data->transformed_checksum, data->length);
    case 3:
        return secret_operation(data);
    default:
        puts("Unknown operation; using addition.");
        return add_values(data->transformed_checksum, data->length);
    }
}

void print_result(const struct InputData *data, unsigned int result)
{
    printf("Processed: %s\n", data->transformed);
    printf("Length: %u; checksum: %u; transformed checksum: %u\n",
           data->length, data->checksum, data->transformed_checksum);
    printf("Result: %u\n", result);
}

int main(int argc, char **argv)
{
    struct InputData data = {0};
    unsigned int operation;
    unsigned int result;

    initialize_app();
    if (argc != 3) {
        puts("Usage: aire_test_binary TEXT OPERATION (1=add, 2=multiply, 3=secret)");
        return 1;
    }
    if (strlen(argv[2]) != 1 || argv[2][0] < '0' || argv[2][0] > '9') {
        puts("Operation must be one digit (0-9).");
        return 1;
    }
    operation = (unsigned int)(argv[2][0] - '0');
    if (!process_input(argv[1], &data)) {
        return 1;
    }
    result = choose_operation(operation, &data);
    print_result(&data, result);
    return 0;
}
