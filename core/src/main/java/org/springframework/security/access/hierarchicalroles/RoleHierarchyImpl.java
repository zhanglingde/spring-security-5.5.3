/*
 * Copyright 2002-2019 the original author or authors.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *      https://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

package org.springframework.security.access.hierarchicalroles;

import java.util.ArrayList;
import java.util.Collection;
import java.util.HashMap;
import java.util.HashSet;
import java.util.Map;
import java.util.Set;

import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;

import org.springframework.core.log.LogMessage;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.AuthorityUtils;
import org.springframework.security.core.authority.SimpleGrantedAuthority;

/**
 * <p>
 * This class defines a role hierarchy for use with various access checking components.
 *
 * <p>
 * Here is an example configuration of a role hierarchy (hint: read the "&gt;" sign as
 * "includes"):
 *
 * <pre>
 *     &lt;property name="hierarchy"&gt;
 *         &lt;value&gt;
 *             ROLE_A &gt; ROLE_B
 *             ROLE_B &gt; ROLE_AUTHENTICATED
 *             ROLE_AUTHENTICATED &gt; ROLE_UNAUTHENTICATED
 *         &lt;/value&gt;
 *     &lt;/property&gt;
 * </pre>
 *
 * <p>
 * Explanation of the above:
 * <ul>
 * <li>In effect every user with ROLE_A also has ROLE_B, ROLE_AUTHENTICATED and
 * ROLE_UNAUTHENTICATED;</li>
 * <li>every user with ROLE_B also has ROLE_AUTHENTICATED and ROLE_UNAUTHENTICATED;</li>
 * <li>every user with ROLE_AUTHENTICATED also has ROLE_UNAUTHENTICATED.</li>
 * </ul>
 *
 * <p>
 * Hierarchical Roles will dramatically shorten your access rules (and also make the
 * access rules much more elegant).
 *
 * <p>
 * Consider this access rule for Spring Security's RoleVoter (background: every user that
 * is authenticated should be able to log out):
 * <pre>/logout.html=ROLE_A,ROLE_B,ROLE_AUTHENTICATED</pre>
 *
 * With hierarchical roles this can now be shortened to:
 * <pre>/logout.html=ROLE_AUTHENTICATED</pre>
 *
 * In addition to shorter rules this will also make your access rules more readable and
 * your intentions clearer.
 *
 * @author Michael Mayr
 */
public class RoleHierarchyImpl implements RoleHierarchy {

	private static final Log logger = LogFactory.getLog(RoleHierarchyImpl.class);

	/**
	 * Raw hierarchy configuration where each line represents single or multiple level
	 * role chain.
	 */
	private String roleHierarchyStringRepresentation = null;

	/**
	 * {@code rolesReachableInOneStepMap} is a Map that under the key of a specific role
	 * name contains a set of all roles reachable from this role in 1 step (i.e. parsed
	 * {@link #roleHierarchyStringRepresentation} grouped by the higher role)
	 */
	private Map<String, Set<GrantedAuthority>> rolesReachableInOneStepMap = null;

	/**
	 * {@code rolesReachableInOneOrMoreStepsMap} is a Map that under the key of a specific
	 * role name contains a set of all roles reachable from this role in 1 or more steps
	 * (i.e. fully resolved hierarchy from {@link #rolesReachableInOneStepMap})
	 */
	private Map<String, Set<GrantedAuthority>> rolesReachableInOneOrMoreStepsMap = null;

	/**
	 * 设置角色间的继承关系
	 * setHierarchy("ROLE_A > ROLE_B > ROLE_C > ROLE_D")
	 *
	 * Set the role hierarchy and pre-calculate for every role the set of all reachable
	 * roles, i.e. all roles lower in the hierarchy of every given role. Pre-calculation
	 * is done for performance reasons (reachable roles can then be calculated in O(1)
	 * time). During pre-calculation, cycles in role hierarchy are detected and will cause
	 * a <tt>CycleInRoleHierarchyException</tt> to be thrown.
	 * @param roleHierarchyStringRepresentation - String definition of the role hierarchy.
	 */
	public void setHierarchy(String roleHierarchyStringRepresentation) {
		// 1. "ROLE_A > ROLE_B > ROLE_C > ROLE_D"
		this.roleHierarchyStringRepresentation = roleHierarchyStringRepresentation;
		logger.debug(LogMessage.format("setHierarchy() - The following role hierarchy was set: %s", roleHierarchyStringRepresentation));
		// 2. 将 roleHierarchyStringRepresentation 角色关系字符串解析成 Map 集合
		buildRolesReachableInOneStepMap();
		// 3. 对 Map 集合进行解析,转换成角色
		buildRolesReachableInOneOrMoreStepsMap();
	}

	@Override
	public Collection<GrantedAuthority> getReachableGrantedAuthorities(
			Collection<? extends GrantedAuthority> authorities) {
		if (authorities == null || authorities.isEmpty()) {
			return AuthorityUtils.NO_AUTHORITIES;
		}
		Set<GrantedAuthority> reachableRoles = new HashSet<>();
		Set<String> processedNames = new HashSet<>();
		for (GrantedAuthority authority : authorities) {
			// Do not process authorities without string representation
			if (authority.getAuthority() == null) {
				reachableRoles.add(authority);
				continue;
			}
			// Do not process already processed roles
			if (!processedNames.add(authority.getAuthority())) {
				continue;
			}
			// Add original authority
			reachableRoles.add(authority);
			// Add roles reachable in one or more steps
			Set<GrantedAuthority> lowerRoles = this.rolesReachableInOneOrMoreStepsMap.get(authority.getAuthority());
			if (lowerRoles == null) {
				continue; // No hierarchy for the role
			}
			for (GrantedAuthority role : lowerRoles) {
				if (processedNames.add(role.getAuthority())) {
					reachableRoles.add(role);
				}
			}
		}
		logger.debug(LogMessage.format("getReachableGrantedAuthorities() - From the roles %s one can reach %s in zero or more steps.", authorities, reachableRoles));
		return new ArrayList<>(reachableRoles);
	}

	/**
	 * 构建角色间的关系（继承依赖关系）
	 *
	 * ROLE_A -> ROLE_B
	 * ROLE_B -> ROLE_C
	 * ROLE_C -> ROLE_D
	 *
	 * Parse input and build the map for the roles reachable in one step: the higher role
	 * will become a key that references a set of the reachable lower roles.
	 */
	private void buildRolesReachableInOneStepMap() {
		// "ROLE_A > ROLE_B > ROLE_C > ROLE_D"(ROLE_A 角色权限最高)
		this.rolesReachableInOneStepMap = new HashMap<>();
		for (String line : this.roleHierarchyStringRepresentation.split("\n")) {
			// Split on > and trim excessive whitespace
			// 1. 一行中按 > 符号拆分成数组
			String[] roles = line.trim().split("\\s+>\\s+");
			for (int i = 1; i < roles.length; i++) {
				String higherRole = roles[i - 1];
				GrantedAuthority lowerRole = new SimpleGrantedAuthority(roles[i]);
				Set<GrantedAuthority> rolesReachableInOneStepSet;
				if (!this.rolesReachableInOneStepMap.containsKey(higherRole)) {
					rolesReachableInOneStepSet = new HashSet<>();
					// 2. 将字符串解析成 ROLE_A -> ROLE_B
					this.rolesReachableInOneStepMap.put(higherRole, rolesReachableInOneStepSet);
				}
				else {
					rolesReachableInOneStepSet = this.rolesReachableInOneStepMap.get(higherRole);
				}
				// 一个角色下一级有多个角色,设置为一个 set
				rolesReachableInOneStepSet.add(lowerRole);
				logger.debug(LogMessage.format("buildRolesReachableInOneStepMap() - From role %s one can reach role %s in one step.", higherRole, lowerRole));
			}
		}
	}

	/**
	 * 对 Map 的角色依赖关系进行解析
	 *
	 * ROLE_A -> [ROLE_B,ROLE_C,ROLE_D]
	 * ROLE_B -> [ROLE_C,ROLE_D]
	 * ROLE_C -> [ROLE_D]
	 *
	 * For every higher role from rolesReachableInOneStepMap store all roles that are
	 * reachable from it in the map of roles reachable in one or more steps. (Or throw a
	 * CycleInRoleHierarchyException if a cycle in the role hierarchy definition is
	 * detected)
	 */
	private void buildRolesReachableInOneOrMoreStepsMap() {
		this.rolesReachableInOneOrMoreStepsMap = new HashMap<>();
		// iterate over all higher roles from rolesReachableInOneStepMap
		for (String roleName : this.rolesReachableInOneStepMap.keySet()) {
			// 1. 子级角色列表
			Set<GrantedAuthority> rolesToVisitSet = new HashSet<>(this.rolesReachableInOneStepMap.get(roleName));
			Set<GrantedAuthority> visitedRolesSet = new HashSet<>();
			while (!rolesToVisitSet.isEmpty()) {
				// take a role from the rolesToVisit set
				GrantedAuthority lowerRole = rolesToVisitSet.iterator().next();
				rolesToVisitSet.remove(lowerRole);
				// 2. 已经添加过 || 子级角色没有权限了则跳过
				if (!visitedRolesSet.add(lowerRole)
						|| !this.rolesReachableInOneStepMap.containsKey(lowerRole.getAuthority())) {
					continue; // Already visited role or role with missing hierarchy
				}
				else if (roleName.equals(lowerRole.getAuthority())) {
					// 角色依赖关系循环了,报错
					throw new CycleInRoleHierarchyException();
				}
				// 3. 递归将子级角色的子级添加进来,进行遍历
				rolesToVisitSet.addAll(this.rolesReachableInOneStepMap.get(lowerRole.getAuthority()));
			}
			// 4. 遍历结束,重新构建依赖关系: ROLE_A -> ROLE_B,ROLE_C,ROLE_D
			this.rolesReachableInOneOrMoreStepsMap.put(roleName, visitedRolesSet);
			logger.debug(LogMessage.format("buildRolesReachableInOneOrMoreStepsMap() - From role %s one can reach %s in one or more steps.", roleName, visitedRolesSet));
		}

	}

}
