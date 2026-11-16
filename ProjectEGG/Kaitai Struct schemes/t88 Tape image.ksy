meta:
  id: t88
  file-extension: t88
  endian: le
  encoding: ascii

seq:
  - id: header
    size: 24
    type: str
    encoding: ascii
  - id: version
    size: 6
  - id: tags
    type: tag
    repeat: until
    repeat-until: _.is_end

types:
  tag:
    seq:
      - id: id
        type: u2
      - id : pad2
        type: u2
      - id: areastarttime
        type: u2
        if: id != 0
      - id: reserved
        size: 2
        if: id != 0
      - id: area_length
        type: u2
        if: id != 0
      - id: pad3
        type: u2      
        if: id != 0
      - id: length
        type: u2
        if: id == 257
      - id: baud
        type: u2
        if: id == 257
      - id: data
        size: length
        if: id == 257

    instances:
      is_end:
        value: id == 0
