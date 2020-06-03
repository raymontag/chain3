//
//  ViewController.m
//  chain3
//
//  Created by Karsten
//  Copyright © 2019 foxhound. All rights reserved.
//

#include <stdio.h>
#include <pthread.h>

#include "exploit.h"
#include "helper.h"
#import "ViewController.h"

@interface ViewController ()

@end

@implementation ViewController

- (id)initWithNav:(UINavigationController *)nav
{
    id ret = [super init];
    self.nav = nav;

    return ret;
}

// void *exploit_thread(void *arg)
// {
//     kern_return_t ret;

//     ret = exploit();
//     if (ret != KERN_SUCCESS)
//     {
//         ERROR_LOG("failed to run exploit: %x", ret);
//     }

//     return NULL;
// }

- (void)viewDidLoad
{
    [super viewDidLoad];

    // ERROR_LOG2("failed to run exploit");
    // pthread_t thd;
    // pthread_create(&thd, NULL, &exploit_thread, NULL);
}

@end
