FROM debian:stretch@sha256:de3eac83cd481c04c5d6c7344cd7327625a1d8b2540e82a8231b5675cef0ae5f

COPY stretch_deps.sh /deps.sh
RUN /deps.sh && rm /deps.sh
VOLUME /walletcordova
ENV JAVA_HOME=/usr/lib/jvm/java-1.8.0-openjdk-amd64
ENV ANDROID_NDK=/opt/android-ndk-r14b
ENV ANDROID_HOME=/opt
CMD cd /walletcordova && ./prepare.sh && cordova prepare android && cordova build android
