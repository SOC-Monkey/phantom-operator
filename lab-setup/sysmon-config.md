# Sysmon Config

**The detection suite uses the following config for sysmon:**

```xml
<Sysmon schemaversion="4.90">
  <EventFiltering>
    <ProcessCreate onmatch="exclude"></ProcessCreate>
    <RegistryEvent onmatch="include">
      <TargetObject condition="contains">CurrentVersion\Run</TargetObject>
    </RegistryEvent>
    <ImageLoad onmatch="include">
      <Image condition="contains">C:\</Image>
    </ImageLoad>
    <FileCreate onmatch="exclude"></FileCreate>
    <FileCreateStreamHash onmatch="exclude"></FileCreateStreamHash>
    <WmiEvent onmatch="exclude"></WmiEvent>
  </EventFiltering>
</Sysmon>
```