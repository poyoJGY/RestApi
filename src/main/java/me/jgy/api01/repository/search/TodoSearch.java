package me.jgy.api01.repository.search;

import me.jgy.api01.dto.PageRequestDTO;
import me.jgy.api01.dto.TodoDTO;
import org.springframework.data.domain.Page;

public interface TodoSearch {

    Page<TodoDTO> list(PageRequestDTO pageRequestDTO);
}
