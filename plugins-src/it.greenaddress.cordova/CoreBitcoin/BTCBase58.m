// Oleg Andreev <oleganza@gmail.com>

#import "BTCBase58.h"
#import "BTCData.h"
#import "libbase58.h"

static const char* BTCBase58Alphabet = "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz";

NSMutableData* BTCDataFromBase58(NSString* string) {
    return BTCDataFromBase58CString([string cStringUsingEncoding:NSASCIIStringEncoding]);
}

NSMutableData* BTCDataFromBase58Check(NSString* string) {
    return BTCDataFromBase58CheckCString([string cStringUsingEncoding:NSASCIIStringEncoding]);
}

NSMutableData* BTCDataFromBase58CString(const char* cstring) {
    if (cstring == NULL) return nil;
    
    // empty string -> empty data.
    if (cstring[0] == '\0') return [NSMutableData data];
    
    unsigned char* bin = malloc(strlen(cstring));
    size_t binsz = strlen(cstring);
    b58tobin(bin, &binsz, cstring, strlen(cstring));
    // "the full binary buffer will be used" which means it has leading zeroes,
    // so they need to be skipped now (strlen(cstring) - binsz):
    NSMutableData* result = [NSMutableData
                             dataWithBytes:bin+(strlen(cstring) - binsz)
                                    length:binsz];
    free(bin);
    return result;
}

NSMutableData* BTCDataFromBase58CheckCString(const char* cstring) {
    if (cstring == NULL) return nil;
    
    NSMutableData* result = BTCDataFromBase58CString(cstring);
    size_t length = result.length;
    if (length < 4) {
        return nil;
    }
    NSData* hash = BTCHash256([result subdataWithRange:NSMakeRange(0, length - 4)]);
    
    // Last 4 bytes should be equal first 4 bytes of the hash.
    if (memcmp(hash.bytes, result.bytes + length - 4, 4) != 0) {
        return nil;
    }
    [result setLength:length - 4];
    return result;
}


char* BTCBase58CStringWithData(NSData* data) {
    if (!data) return NULL;
    
    char *b58 = malloc([data length]*10);
    size_t b58sz = [data length]*10;
    b58enc(b58, &b58sz, [data bytes], [data length]);
    return b58;
}

// String in Base58 with checksum
char* BTCBase58CheckCStringWithData(NSData* immutabledata) {
    if (!immutabledata) return NULL;
    // add 4-byte hash check to the end
    NSMutableData* data = [immutabledata mutableCopy];
    NSData* checksum = BTCHash256(data);
    [data appendBytes:checksum.bytes length:4];
    char* result = BTCBase58CStringWithData(data);
    BTCDataClear(data);
    return result;
}

NSString* BTCBase58StringWithData(NSData* data) {
    if (!data) return nil;
    char* s = BTCBase58CStringWithData(data);
    id r = [NSString stringWithCString:s encoding:NSASCIIStringEncoding];
    BTCSecureClearCString(s);
    free(s);
    return r;
}


NSString* BTCBase58CheckStringWithData(NSData* data) {
    if (!data) return nil;
    char* s = BTCBase58CheckCStringWithData(data);
    id r = [NSString stringWithCString:s encoding:NSASCIIStringEncoding];
    BTCSecureClearCString(s);
    free(s);
    return r;
}






