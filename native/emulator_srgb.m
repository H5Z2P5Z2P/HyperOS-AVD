// Correct owned emulator window presentation without changing Android pixels.
#import <AppKit/AppKit.h>
#import <QuartzCore/QuartzCore.h>
#import <objc/runtime.h>
#include <CommonCrypto/CommonDigest.h>
#include <dlfcn.h>
#include <errno.h>
#include <fcntl.h>
#include <mach/mach.h>
#include <mach/mach_vm.h>
#include <mach-o/loader.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <unistd.h>

static void (*originalViewDidMoveToWindow)(id, SEL);

static void (*originalCombinedSize)(uint32_t *, uint32_t *);
static int (*primaryDisplayPose)(uint32_t, int32_t *, int32_t *, uint32_t *, uint32_t *);
static bool (*separateDisplayWindows)(void);
static uintptr_t rotationSizeCallers[2];

static bool (*nextDisplay)(int32_t, uint32_t *, int32_t *, int32_t *,
                           uint32_t *, uint32_t *, uint32_t *, uint32_t *, uint32_t *);
static bool (*displayInfo)(uint32_t, int32_t *, int32_t *, uint32_t *, uint32_t *,
                           uint32_t *, uint32_t *, bool *);
// ARM64 passes large value structs indirectly. The producer proves this
// calling convention and derives the complete SkinEvent layout from code.
static void (*queueSkinEvent)(const void *);
static size_t skinEventSize, skinEventTypeOffset, skinEventIdOffset;
static size_t skinEventWidthOffset, skinEventHeightOffset;
static uint32_t skinEventAdd, skinEventRemove;

static void queueDisplayRegistration(uint32_t id, uint32_t width, uint32_t height) {
    unsigned char *event = calloc(1, skinEventSize);
    if (!event) return;
    memcpy(event + skinEventTypeOffset, &skinEventRemove, sizeof(skinEventRemove));
    memcpy(event + skinEventIdOffset, &id, sizeof(id));
    queueSkinEvent(event);
    memcpy(event + skinEventTypeOffset, &skinEventAdd, sizeof(skinEventAdd));
    memcpy(event + skinEventWidthOffset, &width, sizeof(width));
    memcpy(event + skinEventHeightOffset, &height, sizeof(height));
    queueSkinEvent(event);
    free(event);
}

static void restoreSecondaryInputs(void) {
    int32_t previous = -1;
    uint32_t id = 0, width = 0, height = 0, dpi = 0, flags = 0, buffer = 0;
    int32_t x = 0, y = 0;
    while (nextDisplay(previous, &id, &x, &y, &width, &height, &dpi, &flags, &buffer)) {
        if (id > INT32_MAX || (previous >= 0 && id <= (uint32_t)previous)) break;
        previous = (int32_t)id;
        bool enabled = false;
        if (!id || !buffer || !displayInfo(id, &x, &y, &width, &height, &dpi, &flags, &enabled) ||
            !enabled || !width || !height) continue;
        // Rotation rebuilds the skin layout and drops its secondary hit-test
        // map. Restore it after the queued layout reset, using natural panel
        // dimensions. These events only manage host input registration: they
        // neither hotplug a guest display nor recreate its Qt window.
        queueDisplayRegistration(id, width, height);
    }
}

static bool primaryRotationSize(uintptr_t caller, uint32_t *width, uint32_t *height) {
    // Keep the aggregate-size contract for recording, rendering and combined
    // windows. Only rotateSkin's two resizes need the independent primary pose.
    if ((caller == rotationSizeCallers[0] || caller == rotationSizeCallers[1]) &&
        separateDisplayWindows()) {
        int32_t x = 0, y = 0;
        uint32_t w = 0, h = 0;
        // getMultiDisplay reports natural dimensions. getDisplayPose reports
        // the current rotated dimensions required by the second resize call.
        if (primaryDisplayPose(0, &x, &y, &w, &h) == 0 && w && h) {
            *width = w;
            *height = h;
            if (caller == rotationSizeCallers[1]) restoreSecondaryInputs();
            return true;
        }
    }
    return false;
}

__attribute__((noinline)) static void primaryWindowSize(uint32_t *width, uint32_t *height) {
    uintptr_t caller = (uintptr_t)__builtin_extract_return_addr(__builtin_return_address(0));
    if (!primaryRotationSize(caller, width, height)) {
        originalCombinedSize(width, height);
    }
}

static bool recipeUInt(id value, uint64_t maximum, uint64_t *result) {
    if (![value isKindOfClass:NSNumber.class] ||
        CFGetTypeID((__bridge CFTypeRef)value) == CFBooleanGetTypeID() ||
        CFNumberIsFloatType((__bridge CFNumberRef)value) || [value longLongValue] < 0) return false;
    uint64_t number = [value unsignedLongLongValue];
    if (number > maximum) return false;
    *result = number;
    return true;
}

static bool imageRange(const struct mach_header_64 *header, uint64_t preferred,
                       uint64_t offset, uint64_t size, bool executable) {
    if (!header || header->magic != MH_MAGIC_64 || header->cputype != CPU_TYPE_ARM64 ||
        header->filetype != MH_EXECUTE || header->sizeofcmds > 65536 ||
        !size || offset > UINTPTR_MAX - (uintptr_t)header ||
        size > UINTPTR_MAX - ((uintptr_t)header + offset))
        return false;
    const unsigned char *cursor = (const unsigned char *)(header + 1);
    const unsigned char *end = cursor + header->sizeofcmds;
    bool found = false, baseMapped = false;
    for (uint32_t i = 0; i < header->ncmds; ++i) {
        if ((size_t)(end - cursor) < sizeof(struct load_command)) return false;
        const struct load_command *command = (const struct load_command *)cursor;
        if (command->cmdsize < sizeof(*command) || command->cmdsize > (size_t)(end - cursor))
            return false;
        if (command->cmd == LC_SEGMENT_64 && command->cmdsize >= sizeof(struct segment_command_64)) {
            const struct segment_command_64 *segment = (const struct segment_command_64 *)command;
            if (!segment->fileoff && segment->filesize >= sizeof(*header) + header->sizeofcmds &&
                segment->vmaddr == preferred) baseMapped = true;
            if (segment->vmaddr >= preferred) {
                uint64_t begin = segment->vmaddr - preferred;
                if (offset >= begin && offset - begin <= segment->vmsize &&
                    size <= segment->vmsize - (offset - begin) &&
                    (segment->initprot & VM_PROT_READ) &&
                    !!(segment->initprot & VM_PROT_EXECUTE) == executable) found = true;
            }
        }
        cursor += command->cmdsize;
    }
    return cursor == end && baseMapped && found;
}

static bool hashMatches(const void *data, size_t size, id expected) {
    if (![expected isKindOfClass:NSString.class] || [expected length] != CC_SHA256_DIGEST_LENGTH * 2 ||
        size > UINT32_MAX) return false;
    unsigned char digest[CC_SHA256_DIGEST_LENGTH];
    CC_SHA256(data, (CC_LONG)size, digest);
    char text[CC_SHA256_DIGEST_LENGTH * 2 + 1];
    for (size_t i = 0; i < sizeof(digest); ++i) snprintf(text + i * 2, 3, "%02x", digest[i]);
    return !strcmp(text, [expected UTF8String]);
}

static bool executableMatches(const char *path, id expected) {
    if (![expected isKindOfClass:NSString.class] || [expected length] != CC_SHA256_DIGEST_LENGTH * 2)
        return false;
    int descriptor = open(path, O_RDONLY | O_CLOEXEC);
    if (descriptor < 0) return false;
    CC_SHA256_CTX context;
    CC_SHA256_Init(&context);
    unsigned char buffer[65536];
    ssize_t count;
    while ((count = read(descriptor, buffer, sizeof(buffer))) != 0) {
        if (count < 0) {
            if (errno == EINTR) continue;
            close(descriptor);
            return false;
        }
        CC_SHA256_Update(&context, buffer, (CC_LONG)count);
    }
    close(descriptor);
    unsigned char digest[CC_SHA256_DIGEST_LENGTH];
    CC_SHA256_Final(digest, &context);
    char text[CC_SHA256_DIGEST_LENGTH * 2 + 1];
    for (size_t i = 0; i < sizeof(digest); ++i) snprintf(text + i * 2, 3, "%02x", digest[i]);
    return !strcmp(text, [expected UTF8String]);
}

static NSDictionary *displayRecipe(void) {
    const char *path = getenv("HYPEROS_AVD_DISPLAY_RECIPE");
    if (!path || !*path) return nil;
    int descriptor = open(path, O_RDONLY | O_NOFOLLOW | O_CLOEXEC);
    if (descriptor < 0) return nil;
    struct stat entry;
    if (fstat(descriptor, &entry) || !S_ISREG(entry.st_mode) || entry.st_uid != getuid() ||
        entry.st_nlink != 1 || (entry.st_mode & 077) || entry.st_size <= 0 || entry.st_size > 262144) {
        close(descriptor);
        return nil;
    }
    NSMutableData *data = [NSMutableData dataWithLength:(NSUInteger)entry.st_size];
    size_t used = 0;
    while (used < data.length) {
        ssize_t count = read(descriptor, (unsigned char *)data.mutableBytes + used, data.length - used);
        if (count < 0 && errno == EINTR) continue;
        if (count <= 0) { close(descriptor); return nil; }
        used += (size_t)count;
    }
    close(descriptor);
    id result = [NSJSONSerialization JSONObjectWithData:data options:0 error:NULL];
    return [result isKindOfClass:NSDictionary.class] ? result : nil;
}

static bool verifiedCode(const struct mach_header_64 *header, uint64_t preferred, NSDictionary *row) {
    if (![row isKindOfClass:NSDictionary.class]) return false;
    uint64_t offset, size;
    if (!recipeUInt(row[@"offset"], UINTPTR_MAX, &offset) ||
        !recipeUInt(row[@"size"], 1048576, &size) || !imageRange(header, preferred, offset, size, true))
        return false;
    return hashMatches((const unsigned char *)header + offset, (size_t)size, row[@"sha256"]);
}

static uintptr_t recipeBinding(NSDictionary *recipe, NSString *role) {
    id name = recipe[@"bindings"][role];
    return [name isKindOfClass:NSString.class] ? (uintptr_t)dlsym(RTLD_DEFAULT, [name UTF8String]) : 0;
}

static bool installDisplayRecipe(NSDictionary *recipe, const uintptr_t *const *exported, Dl_info image) {
    uint64_t schema, preferred, globalOffset, tableOffset, tableSize;
    if (!recipeUInt(recipe[@"schema"], 1, &schema) || schema != 1 ||
        !recipeUInt(recipe[@"image_preferred_base"], UINTPTR_MAX, &preferred) ||
        !executableMatches(image.dli_fname, recipe[@"binary_sha256"])) return false;
    const struct mach_header_64 *header = image.dli_fbase;
    uintptr_t base = (uintptr_t)header;
    NSDictionary *symbols = recipe[@"symbols"], *agent = recipe[@"agent"], *bindings = recipe[@"bindings"];
    if (![symbols isKindOfClass:NSDictionary.class] || !symbols.count || symbols.count > 64 ||
        ![agent isKindOfClass:NSDictionary.class] || ![bindings isKindOfClass:NSDictionary.class] ||
        !recipeUInt(agent[@"global_offset"], UINTPTR_MAX, &globalOffset) ||
        !imageRange(header, preferred, globalOffset, sizeof(uintptr_t), false) ||
        (uintptr_t)exported != base + globalOffset ||
        !recipeUInt(agent[@"table_offset"], UINTPTR_MAX, &tableOffset) ||
        !recipeUInt(agent[@"table_size"], 4096, &tableSize) || tableSize % sizeof(uintptr_t) ||
        !imageRange(header, preferred, tableOffset, tableSize, false) ||
        (uintptr_t)*exported != base + tableOffset) return false;
    for (NSString *name in symbols) {
        if (![name isKindOfClass:NSString.class] || !name.length || name.length > 1024 ||
            !verifiedCode(header, preferred, symbols[name])) return false;
        uint64_t offset;
        if (!recipeUInt(symbols[name][@"offset"], UINTPTR_MAX, &offset) ||
            (uintptr_t)dlsym(RTLD_DEFAULT, name.UTF8String) != base + offset) return false;
    }
    for (NSString *role in bindings) {
        id name = bindings[role];
        if (![name isKindOfClass:NSString.class] || !symbols[name]) return false;
    }
    NSDictionary *slots = agent[@"slots"], *entries = agent[@"entries"];
    if (![slots isKindOfClass:NSDictionary.class] || ![entries isKindOfClass:NSDictionary.class]) return false;
    const uintptr_t *table = *exported;
    NSMutableSet *usedSlots = [NSMutableSet set];
    for (NSString *role in @[@"combined", @"pose", @"separate_windows", @"next_display", @"display_info", @"perform_rotation"]) {
        uint64_t slot, offset;
        if (!recipeUInt(slots[role], tableSize / sizeof(uintptr_t) - 1, &slot) ||
            [usedSlots containsObject:@(slot)] || !verifiedCode(header, preferred, entries[role]) ||
            !recipeUInt(entries[role][@"offset"], UINTPTR_MAX, &offset) || table[slot] != base + offset ||
            !recipeBinding(recipe, role)) return false;
        [usedSlots addObject:@(slot)];
    }
    id callers = recipe[@"rotation_callers"];
    NSString *rotationName = bindings[@"rotate"];
    NSDictionary *rotation = [rotationName isKindOfClass:NSString.class] ? symbols[rotationName] : nil;
    uint64_t rotationOffset, rotationSize;
    if (![callers isKindOfClass:NSArray.class] || [callers count] != 2 || !rotation ||
        !recipeUInt(rotation[@"offset"], UINTPTR_MAX, &rotationOffset) ||
        !recipeUInt(rotation[@"size"], 1048576, &rotationSize)) return false;
    uint64_t callOffsets[2];
    for (unsigned int i = 0; i < 2; ++i) {
        if (!recipeUInt(callers[i], rotationSize, &callOffsets[i]) || callOffsets[i] < 4 || callOffsets[i] % 4)
            return false;
        uint32_t instruction;
        memcpy(&instruction, (const unsigned char *)header + rotationOffset + callOffsets[i] - 4, 4);
        if ((instruction & 0xfffffc1f) != 0xd63f0000) return false;
    }
    if (callOffsets[0] >= callOffsets[1]) return false;
    NSDictionary *event = recipe[@"event"];
    uint64_t eventSize, eventOffsets[4], eventAdd, eventRemove;
    if (![event isKindOfClass:NSDictionary.class] ||
        !recipeUInt(event[@"size"], 512, &eventSize) || eventSize <= 16 || eventSize % 8 ||
        !recipeUInt(event[@"add_type"], INT32_MAX, &eventAdd) ||
        !recipeUInt(event[@"remove_type"], INT32_MAX, &eventRemove) || eventAdd == eventRemove ||
        !recipeBinding(recipe, @"event")) return false;
    NSArray *eventFields = @[@"type_offset", @"id_offset", @"width_offset", @"height_offset"];
    for (unsigned int i = 0; i < 4; ++i) {
        if (!recipeUInt(event[eventFields[i]], eventSize - 4, &eventOffsets[i]) || eventOffsets[i] % 4) return false;
        for (unsigned int j = 0; j < i; ++j) if (eventOffsets[j] == eventOffsets[i]) return false;
    }
    uint64_t combinedSlot = [slots[@"combined"] unsignedLongLongValue];
    originalCombinedSize = (void (*)(uint32_t *, uint32_t *))table[combinedSlot];
    primaryDisplayPose = (int (*)(uint32_t, int32_t *, int32_t *, uint32_t *, uint32_t *))table[[slots[@"pose"] unsignedLongLongValue]];
    separateDisplayWindows = (bool (*)(void))table[[slots[@"separate_windows"] unsignedLongLongValue]];
    displayInfo = (bool (*)(uint32_t, int32_t *, int32_t *, uint32_t *, uint32_t *, uint32_t *, uint32_t *, bool *))table[[slots[@"display_info"] unsignedLongLongValue]];
    nextDisplay = (bool (*)(int32_t, uint32_t *, int32_t *, int32_t *, uint32_t *, uint32_t *, uint32_t *, uint32_t *, uint32_t *))table[[slots[@"next_display"] unsignedLongLongValue]];
    queueSkinEvent = (void (*)(const void *))recipeBinding(recipe, @"event");
    rotationSizeCallers[0] = base + rotationOffset + callOffsets[0];
    rotationSizeCallers[1] = base + rotationOffset + callOffsets[1];
    skinEventSize = (size_t)eventSize;
    skinEventTypeOffset = (size_t)eventOffsets[0];
    skinEventIdOffset = (size_t)eventOffsets[1];
    skinEventWidthOffset = (size_t)eventOffsets[2];
    skinEventHeightOffset = (size_t)eventOffsets[3];
    skinEventAdd = (uint32_t)eventAdd;
    skinEventRemove = (uint32_t)eventRemove;

    // Change one data pointer, never executable instructions or SDK files.
    mach_vm_address_t slotAddress = (mach_vm_address_t)&table[combinedSlot], region = slotAddress;
    mach_vm_size_t regionSize = 0;
    vm_region_basic_info_data_64_t info;
    mach_msg_type_number_t count = VM_REGION_BASIC_INFO_COUNT_64;
    mach_port_t object = MACH_PORT_NULL;
    kern_return_t status = mach_vm_region(mach_task_self(), &region, &regionSize,
        VM_REGION_BASIC_INFO_64, (vm_region_info_t)&info, &count, &object);
    if (object != MACH_PORT_NULL) mach_port_deallocate(mach_task_self(), object);
    if (status != KERN_SUCCESS || slotAddress < region || slotAddress + sizeof(uintptr_t) > region + regionSize ||
        !(info.protection & VM_PROT_READ) || (info.protection & VM_PROT_EXECUTE)) return false;
    mach_vm_address_t page = slotAddress & ~((mach_vm_address_t)vm_page_size - 1);
    status = mach_vm_protect(mach_task_self(), page, vm_page_size, false,
                            info.protection | VM_PROT_WRITE | VM_PROT_COPY);
    if (status != KERN_SUCCESS) return false;
    uintptr_t replacement = (uintptr_t)primaryWindowSize;
    memcpy((void *)slotAddress, &replacement, sizeof(replacement));
    status = mach_vm_protect(mach_task_self(), page, vm_page_size, false, info.protection);
    if (status != KERN_SUCCESS) {
        memcpy((void *)slotAddress, &originalCombinedSize, sizeof(originalCombinedSize));
        status = mach_vm_protect(mach_task_self(), page, vm_page_size, false, info.protection);
        fprintf(stderr, "HyperOSAVDDisplay: rotation hook rolled back, page restoration status %d\n", status);
        return false;
    }
    return true;
}

static void installPrimaryRotationSize(void) {
    const uintptr_t *const *exported = dlsym(RTLD_DEFAULT, "gQAndroidMultiDisplayAgent");
    if (!exported) return; // The SDK launcher does not own the display agent.
    Dl_info image;
    @autoreleasepool {
        NSDictionary *recipe = displayRecipe();
        if (!recipe || !dladdr(exported, &image) || !installDisplayRecipe(recipe, exported, image)) {
            fprintf(stderr, "HyperOSAVDDisplay: incompatible display ABI or capability receipt\n");
            return;
        }
    }
    fprintf(stderr, "HyperOSAVDDisplay: independent primary-window rotation enabled\n");
}

static void srgbViewDidMoveToWindow(id object, SEL selector) {
    originalViewDidMoveToWindow(object, selector);
    NSView *view = object;
    const char *name = object_getClassName(view);
    if (strcmp(name, "EmuGLView") && strcmp(name, "EmuGLViewWithMetal")) return;
    NSWindow *window = view.window;
    if (!window) return;
    NSColorSpace *srgb = NSColorSpace.sRGBColorSpace;
    if (![window.colorSpace isEqual:srgb]) {
        fprintf(stderr, "HyperOSAVDColor: %s window color space %s -> sRGB\n",
                name, window.colorSpace.localizedName.UTF8String ?: "untagged");
        window.colorSpace = srgb;
    }
    if ([view.layer isKindOfClass:CAMetalLayer.class]) {
        CAMetalLayer *layer = (CAMetalLayer *)view.layer;
        layer.colorspace = srgb.CGColorSpace;
    }
}

__attribute__((constructor)) static void installSrgbTag(void) {
    const char *enabled = getenv("HYPEROS_AVD_SRGB");
    const char *multiDisplay = getenv("HYPEROS_AVD_MULTI_DISPLAY");
    bool colorEnabled = enabled && !strcmp(enabled, "1");
    bool displayEnabled = multiDisplay && !strcmp(multiDisplay, "1");
    if (!colorEnabled && !displayEnabled) return;
    const char *expected = getenv("HYPEROS_AVD_SRGB_AVD");
    if (!expected || !*expected) return;
    NSString *expectedName = [NSString stringWithUTF8String:expected];
    if (!expectedName.length) return;
    NSArray<NSString *> *arguments = NSProcessInfo.processInfo.arguments;
    NSUInteger index = [arguments indexOfObject:@"-avd"];
    if (index == NSNotFound || index + 1 >= arguments.count ||
        ![arguments[index + 1] isEqualToString:expectedName]) return;
    if (displayEnabled) installPrimaryRotationSize();
    if (!colorEnabled) return;
    Method method = class_getInstanceMethod(NSView.class, @selector(viewDidMoveToWindow));
    if (!method) return;
    originalViewDidMoveToWindow = (void (*)(id, SEL))method_getImplementation(method);
    method_setImplementation(method, (IMP)srgbViewDidMoveToWindow);
    fprintf(stderr, "HyperOSAVDColor: sRGB tagging enabled for the owned OS4 AVD %s\n",
            expected);
}
