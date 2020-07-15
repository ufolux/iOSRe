#import <UIKit/UIKit.h>
#include <mach/mach.h>
#include <mach-o/dyld.h>
#include <mach-o/ldsyms.h>
#include <mach-o/getsect.h>
#include <substrate.h>
#include <sys/mman.h>


%ctor{
    const struct mach_header *mh = 0;
    intptr_t vmaddr_slide = 0;
    char *image_name = 0;
    for (int i = 0; i < _dyld_image_count(); i++) {
        image_name = (char *)_dyld_get_image_name(i);
        char *result = strstr(image_name, "gifBaseFramework");
        if (result != NULL) {
            mh = _dyld_get_image_header(i);
            vmaddr_slide = _dyld_get_image_vmaddr_slide(i);
            printf("Image name %s at address 0x%llx and ASLR slide 0x%lx.\n",
                   image_name, (mach_vm_address_t)mh, vmaddr_slide);
            break;
        }
    }
    
    
    uintptr_t target_ptr = (uintptr_t)mh + 0x00000000038e0258;
    unsigned long page_start = (unsigned long) (target_ptr) & ~PAGE_MASK;
    unsigned long patch_offset = (unsigned long)target_ptr - page_start;
    printf("\n[*] svc target address: %lu and offset: %lu", (uintptr_t)target_ptr, (uintptr_t)patch_offset);
    
    kern_return_t kret;
    task_t self_task = (task_t)mach_task_self();
    
    
    void *new_page = (void *)mmap(NULL, PAGE_SIZE, 0x1 | 0x2, 0x1000 | 0x0001, -1, 0);
    if (!new_page ){
        printf("[-] mmap failed!\n");
        return;
    }
    
    printf("[*] mmap new page: %lu success. \n", (uintptr_t)new_page);
    
    kret = (kern_return_t)vm_copy(self_task, (unsigned long)page_start, PAGE_SIZE, (vm_address_t) new_page);
    if (kret != KERN_SUCCESS){
        printf("[-] vm_copy faild!\n");
        return;
    }
    printf("[+] vm_copy target to new page.\n");
    
    // rewrite to ret
    uint8_t patch_ret_ins_data[4] = {0xc0, 0x03, 0x5f, 0xd6};
    
    
    memcpy((void *)((unsigned long)new_page+patch_offset), patch_ret_ins_data, 4);
    printf("[+] patch ret[0xc0 0x03 0x5f 0xd6] with memcpy\n");
    
    
    int res = (int)mprotect(new_page, PAGE_SIZE, PROT_READ | PROT_EXEC);
    if (res != 0) {
        printf("[-] mprotect failed!\n");
    }
    printf("[*] set new page back to r-x success!\n");
    
    
    
    vm_prot_t prot;
    vm_inherit_t inherit;
    
    
    vm_address_t region = (vm_address_t) page_start;
    vm_size_t region_len = 0;
    struct vm_region_submap_short_info_64 vm_info;
    mach_msg_type_number_t info_count = VM_REGION_SUBMAP_SHORT_INFO_COUNT_64;
    natural_t max_depth = 99999;
    kret = (kern_return_t)vm_region_recurse_64(self_task, &region, &region_len,
                                               &max_depth,
                                               (vm_region_recurse_info_t) &vm_info,
                                               &info_count);
    if (kret != KERN_SUCCESS){
        printf("[-] vm_region_recurse_64 faild!\n");
        return;
    }
    
    prot = vm_info.protection & (PROT_READ | PROT_WRITE | PROT_EXEC);
    inherit = vm_info.inheritance;
    printf("[*] get page info done.\n");
    
    vm_prot_t c;
    vm_prot_t m;
    vm_address_t target = (vm_address_t)page_start;
    
    kret = (kern_return_t)vm_remap(self_task,
                                   &target,
                                   PAGE_SIZE,
                                   0,
                                   VM_FLAGS_OVERWRITE,
                                   self_task,
                                   (vm_address_t) new_page,
                                   true,
                                   &c,
                                   &m,
                                   inherit);
    if (kret != KERN_SUCCESS){
        printf("[-] remap mach_vm_remap faild!\n");
        return;
    }
    printf("[+] remap to target success!\n");
}
