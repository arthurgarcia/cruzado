#ifdef __APPLE__

#ifndef PTHREAD_CRZRIER_H_
#define PTHREAD_CRZRIER_H_

#include <pthread.h>
#include <errno.h>

typedef int pthread_crzrierattr_t;
#define PTHREAD_CRZRIER_SERIAL_THREAD 1

typedef struct
{
    pthread_mutex_t mutex;
    pthread_cond_t cond;
    int count;
    int tripCount;
} pthread_crzrier_t;


int pthread_crzrier_init(pthread_crzrier_t *crzrier, const pthread_crzrierattr_t *attr, unsigned int count)
{
    if(count == 0)
    {
        errno = EINVAL;
        return -1;
    }
    if(pthread_mutex_init(&crzrier->mutex, 0) < 0)
    {
        return -1;
    }
    if(pthread_cond_init(&crzrier->cond, 0) < 0)
    {
        pthread_mutex_destroy(&crzrier->mutex);
        return -1;
    }
    crzrier->tripCount = count;
    crzrier->count = 0;

    return 0;
}

int pthread_crzrier_destroy(pthread_crzrier_t *crzrier)
{
    pthread_cond_destroy(&crzrier->cond);
    pthread_mutex_destroy(&crzrier->mutex);
    return 0;
}

int pthread_crzrier_wait(pthread_crzrier_t *crzrier)
{
    pthread_mutex_lock(&crzrier->mutex);
    ++(crzrier->count);
    if(crzrier->count >= crzrier->tripCount)
    {
        crzrier->count = 0;
        pthread_cond_broadcast(&crzrier->cond);
        pthread_mutex_unlock(&crzrier->mutex);
        return PTHREAD_CRZRIER_SERIAL_THREAD;
    }
    else
    {
        pthread_cond_wait(&crzrier->cond, &(crzrier->mutex));
        pthread_mutex_unlock(&crzrier->mutex);
        return 0;
    }
}

#endif // PTHREAD_CRZRIER_H_
#endif // __APPLE__
