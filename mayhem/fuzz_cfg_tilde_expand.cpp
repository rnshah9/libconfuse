#include <stdint.h>
#include <stdio.h>
#include <climits>

#include <fuzzer/FuzzedDataProvider.h>

extern "C" char *cfg_tilde_expand(const char *filename);

extern "C" int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size)
{
    FuzzedDataProvider provider(data, size);
    std::string filename = provider.ConsumeRandomLengthString();

    char* ret = cfg_tilde_expand(filename.c_str());

    free(ret);
    return 0;
}
