SECTIONS
{
  .note.gnu.build-id : { *(.note.gnu.build-id) }
  .note.gnu.property : { *(.note.gnu.property) }
  .note.ABI-tag      : { *(.note.ABI-tag) }
} INSERT AFTER .interp;
