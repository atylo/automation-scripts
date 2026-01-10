meta:
  id: egg_pds_disk # special ProjectEGG format for diskettes, similar to d88
  file-extension: bin
  endian: le

seq:
  - id: magic
    type: str
    encoding: ascii
    size: 3
  - id: versionmb
    type: u1
  - id: some_data2
    type: u1
  - id: track
    type: track
    repeat: until
    repeat-until: _io.eof

  
types:
  track:
    seq:
      - id: num_of_sectors
        type: u1
      - id: sectors
        type: sector
        repeat: expr
        repeat-expr: num_of_sectors
  sector:
    seq:
      - id: sheader
        type: sector_head
      - id: sector_data
        size: 128 * sheader.data_size

  sector_head:
    seq:
      - id: cylinder_id
        type: u1
      - id: head_id
        type: u1
      - id: sector_num
        type: u1
      - id: smth
        type: u1
      - id: smth2
        type: u1
      - id: data_size
        type: u1
    
