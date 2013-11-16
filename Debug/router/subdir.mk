################################################################################
# Automatically-generated file. Do not edit!
################################################################################

# Add inputs and outputs from these tool invocations to the build variables 
C_SRCS += \
../router/sha1.c \
../router/sr_arpcache.c \
../router/sr_dumper.c \
../router/sr_if.c \
../router/sr_main.c \
../router/sr_router.c \
../router/sr_rt.c \
../router/sr_utils.c \
../router/sr_vns_comm.c 

OBJS += \
./router/sha1.o \
./router/sr_arpcache.o \
./router/sr_dumper.o \
./router/sr_if.o \
./router/sr_main.o \
./router/sr_router.o \
./router/sr_rt.o \
./router/sr_utils.o \
./router/sr_vns_comm.o 

C_DEPS += \
./router/sha1.d \
./router/sr_arpcache.d \
./router/sr_dumper.d \
./router/sr_if.d \
./router/sr_main.d \
./router/sr_router.d \
./router/sr_rt.d \
./router/sr_utils.d \
./router/sr_vns_comm.d 


# Each subdirectory must supply rules for building sources it contributes
router/%.o: ../router/%.c
	@echo 'Building file: $<'
	@echo 'Invoking: GCC C Compiler'
	gcc -O0 -g3 -Wall -c -fmessage-length=0 -MMD -MP -MF"$(@:%.o=%.d)" -MT"$(@:%.o=%.d)" -o"$@" "$<"
	@echo 'Finished building: $<'
	@echo ' '


